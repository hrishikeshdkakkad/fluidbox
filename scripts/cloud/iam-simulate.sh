#!/usr/bin/env bash
# Test the deployer/operator IAM policies WITHOUT creating anything.
#
# The independent review flagged IAM sufficiency as the likeliest cause of a
# failed first apply, and two real gaps were then found BY INSPECTION. Reading
# a policy is not testing it: `aws iam simulate-custom-policy` evaluates the
# actual policy documents against the actual actions and ARNs the stacks use,
# and it is a read-only API call — nothing is created, nothing is charged.
#
# Policies are extracted from a live `terraform plan`, not copied into a
# fixture, so this cannot drift from what would actually be applied.
#
# Positive cases: every action the platform/app/edge applies need.
# NEGATIVE cases: prove the scoping actually scopes — the operator must NOT be
# able to build infrastructure, and the deployer must NOT reach IAM outside
# /fluidbox-cloud/ or S3 outside fluidbox-*.
#
#   scripts/cloud/iam-simulate.sh
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.." || exit 1
. scripts/cloud/lib.sh

ACCOUNT="${ACCOUNT_ID:-471112572248}"
REGION="${CLOUD_REGION:-us-east-1}"
WORK="${SCRATCH:-/tmp/fluidbox-iam-sim}"
EV=$(evidence_dir cloud-m1-readiness)
OUT="$EV/iam-simulation.md"
mkdir -p "$WORK"

command -v jq >/dev/null || die "jq required"

PASS=0; FAILN=0
pass() { ok "$1"; PASS=$((PASS+1)); }
bad()  { fail "$1"; FAILN=$((FAILN+1)); }

say "1. extract the REAL policy documents from a terraform plan"
( cd deploy/cloud/terraform/bootstrap && terraform plan -input=false -out="$WORK/boot.tfplan" \
    -var account_budget_limit=400 >/dev/null 2>&1 ) || die "bootstrap plan failed"
( cd deploy/cloud/terraform/bootstrap && terraform show -json "$WORK/boot.tfplan" ) > "$WORK/plan.json" 2>/dev/null \
  || die "terraform show failed"

jq -r '[.planned_values.root_module.resources[]
        | select(.type=="aws_iam_policy" and .name=="deployer_infra")][0].values.policy' \
  "$WORK/plan.json" > "$WORK/deployer-infra.json"
jq -r '[.planned_values.root_module.resources[]
        | select(.type=="aws_iam_policy" and .name=="deployer_iam")][0].values.policy' \
  "$WORK/plan.json" > "$WORK/deployer-iam.json"
jq -r '[.planned_values.root_module.resources[]
        | select(.type=="aws_iam_user_policy" and .name=="operator")][0].values.policy' \
  "$WORK/plan.json" > "$WORK/operator.json"
for f in deployer-infra deployer-iam operator; do
  jq -e . "$WORK/$f.json" >/dev/null 2>&1 || die "could not extract $f policy from the plan"
done
pass "extracted deployer-infra, deployer-iam and operator policies from the plan"

# The deployer is the union of its two attached policies. SimulateCustomPolicy
# caps EACH policyInputList member at 2000 characters, so the statements are
# minified and packed into as many sub-2000-char documents as needed — IAM
# evaluates the union of every member, so this is semantically identical to
# the single policy while staying inside the API limit.
split_policy() { # split_policy <out-prefix> <in.json>...
  python3 - "$@" <<'PY'
import json, sys
prefix, srcs = sys.argv[1], sys.argv[2:]
stmts = []
for s in srcs:
    stmts += json.load(open(s))["Statement"]
chunks, cur = [], []
def render(sts): return json.dumps({"Version": "2012-10-17", "Statement": sts}, separators=(",", ":"))
for st in stmts:
    trial = cur + [st]
    if len(render(trial)) > 1990 and cur:
        chunks.append(cur); cur = [st]
    else:
        cur = trial
    if len(render([st])) > 1990:
        raise SystemExit(f"single statement exceeds the 2000-char simulation limit: {st.get('Sid')}")
if cur: chunks.append(cur)
for i, c in enumerate(chunks):
    open(f"{prefix}{i}.json", "w").write(render(c))
print(len(chunks))
PY
}
DEPLOYER_N=$(split_policy "$WORK/dep-" "$WORK/deployer-infra.json" "$WORK/deployer-iam.json") \
  || die "could not split the deployer policy"
OPERATOR_N=$(split_policy "$WORK/op-" "$WORK/operator.json") \
  || die "could not split the operator policy"
# Inline, not file:// — the CLI does NOT expand file:// for members of a LIST
# parameter, so a path is sent verbatim as the policy body and every call
# fails with "invalid content" rather than anything that names the cause.
DEPLOYER_ARGS=(); for i in $(seq 0 $((DEPLOYER_N - 1))); do DEPLOYER_ARGS+=("$(cat "$WORK/dep-$i.json")"); done
OPERATOR_ARGS=(); for i in $(seq 0 $((OPERATOR_N - 1))); do OPERATOR_ARGS+=("$(cat "$WORK/op-$i.json")"); done
pass "policies packed for simulation (deployer: $DEPLOYER_N documents, operator: $OPERATOR_N)"

sim() { # sim <deployer|operator> <expect allowed|denied> <label> <action> <arn> [ctx-key ctx-val ctx-type]
  local who="$1" expect="$2" label="$3" action="$4" arn="$5"
  local pols=()
  case "$who" in
    deployer) pols=("${DEPLOYER_ARGS[@]}") ;;
    operator) pols=("${OPERATOR_ARGS[@]}") ;;
    *) bad "$label — unknown policy set '$who'"; return ;;
  esac
  local args=(--policy-input-list "${pols[@]}" --action-names "$action" --resource-arns "$arn")
  if [ $# -ge 8 ]; then
    args+=(--context-entries "ContextKeyName=$6,ContextKeyValues=$7,ContextKeyType=$8")
  fi
  local d
  d=$(aws iam simulate-custom-policy "${args[@]}" \
        --query 'EvaluationResults[0].EvalDecision' --output text 2>"$WORK/sim.err")
  [ -z "$d" ] && { bad "$label — simulation ERROR: $(head -1 "$WORK/sim.err")"; return; }
  case "$expect:$d" in
    allowed:allowed)             pass "$label → allowed";;
    denied:implicitDeny|denied:explicitDeny) pass "$label → $d (correctly refused)";;
    *) bad "$label → $d (expected $expect)";;
  esac
  printf '| %s | `%s` | %s | %s |\n' "$label" "$action" "$expect" "$d" >> "$WORK/rows.md"
}

: > "$WORK/rows.md"

say "2. DEPLOYER — actions the platform/app/edge applies actually perform"
R="aws:RequestedRegion"
sim deployer allowed "vpc create"            ec2:CreateVpc            "*" "$R" "$REGION" string
sim deployer allowed "subnet create"         ec2:CreateSubnet         "*" "$R" "$REGION" string
sim deployer allowed "security group create" ec2:CreateSecurityGroup  "*" "$R" "$REGION" string
# CREATE actions are simulated against "*", not against the ARN of the thing
# being created: that resource does not exist at request time, and the IAM
# simulator answers implicitDeny for the action/resource pairing rather than
# for the policy. Passing a cluster ARN here reported four false "gaps" —
# the same statement allows eks:DescribeCluster on that ARN, which is what
# gave the artifact away. Do not "fix" the policy to satisfy a wrong test.
sim deployer allowed "eks cluster create"    eks:CreateCluster        "*" "$R" "$REGION" string
sim deployer allowed "eks nodegroup create"  eks:CreateNodegroup      "*" "$R" "$REGION" string
sim deployer allowed "eks addon create"      eks:CreateAddon          "*" "$R" "$REGION" string
sim deployer allowed "pod identity assoc"    eks:CreatePodIdentityAssociation "*" "$R" "$REGION" string
sim deployer allowed "eks describe (app stack data source)" eks:DescribeCluster "arn:aws:eks:$REGION:$ACCOUNT:cluster/fluidbox-cloud" "$R" "$REGION" string
sim deployer allowed "asg tag (autoscaler discovery)" autoscaling:CreateOrUpdateTags "*" "$R" "$REGION" string
sim deployer allowed "elbv2 describe (edge data source)" elasticloadbalancing:DescribeLoadBalancers "*" "$R" "$REGION" string
sim deployer allowed "kms key create"        kms:CreateKey            "*"
sim deployer allowed "kms alias create"      kms:CreateAlias          "arn:aws:kms:$REGION:$ACCOUNT:alias/fluidbox-cloud-kek"
sim deployer allowed "cloudfront distribution create" cloudfront:CreateDistribution "*"
sim deployer allowed "eks log group create"  logs:CreateLogGroup      "arn:aws:logs:$REGION:$ACCOUNT:log-group:/aws/eks/fluidbox-cloud/cluster"
sim deployer allowed "log retention policy"  logs:PutRetentionPolicy  "arn:aws:logs:$REGION:$ACCOUNT:log-group:/aws/eks/fluidbox-cloud/cluster"
sim deployer allowed "ecr repo create"       ecr:CreateRepository     "arn:aws:ecr:$REGION:$ACCOUNT:repository/fluidbox-replay-runner"
sim deployer allowed "ssm custody write"     ssm:PutParameter         "arn:aws:ssm:$REGION:$ACCOUNT:parameter/fluidbox/cloud/admin-token"
sim deployer allowed "tag discovery (ALB lookup by scripts)" tag:GetResources "*"
sim deployer allowed "root-key check (verify-bootstrap)" iam:GetAccountSummary "*"
sim deployer allowed "state object read"     s3:GetObject             "arn:aws:s3:::fluidbox-cloud-tfstate-$ACCOUNT/platform.tfstate"

say "3. DEPLOYER — IAM plane, scoped to /fluidbox-cloud/"
sim deployer allowed "role create under /fluidbox-cloud/" iam:CreateRole "arn:aws:iam::$ACCOUNT:role/fluidbox-cloud/fluidbox-eks-cluster"
sim deployer allowed "PassRole to EKS" iam:PassRole "arn:aws:iam::$ACCOUNT:role/fluidbox-cloud/fluidbox-eks-cluster" "iam:PassedToService" "eks.amazonaws.com" string
sim deployer allowed "PassRole to Pod Identity" iam:PassRole "arn:aws:iam::$ACCOUNT:role/fluidbox-cloud/fluidbox-server" "iam:PassedToService" "pods.eks.amazonaws.com" string

say "4. NEGATIVE — the scoping must actually scope (these MUST be refused)"
sim deployer denied "role create OUTSIDE the path" iam:CreateRole "arn:aws:iam::$ACCOUNT:role/some-other-project-role"
sim deployer denied "PassRole to an arbitrary service" iam:PassRole "arn:aws:iam::$ACCOUNT:role/fluidbox-cloud/fluidbox-server" "iam:PassedToService" "lambda.amazonaws.com" string
sim deployer denied "PassRole for a NON-fluidbox role" iam:PassRole "arn:aws:iam::$ACCOUNT:role/fluidzero-mcp-github-deploy" "iam:PassedToService" "eks.amazonaws.com" string
sim deployer denied "read ANOTHER project's S3 bucket" s3:GetObject "arn:aws:s3:::fluidzero-terraform-state/terraform.tfstate"
sim deployer denied "delete a user (privilege escalation)" iam:DeleteUser "arn:aws:iam::$ACCOUNT:user/sumeetaher"
sim deployer denied "attach an admin policy to itself" iam:AttachUserPolicy "arn:aws:iam::$ACCOUNT:user/fluidbox-cloud/fluidbox-operator"
sim deployer denied "ec2 outside the pinned region" ec2:CreateVpc "*" "$R" "eu-west-1" string
sim deployer denied "write another project's SSM" ssm:PutParameter "arn:aws:ssm:$REGION:$ACCOUNT:parameter/fluidzero/secret"

say "5. OPERATOR — must be able to bootstrap, and NOTHING else"
sim operator allowed "assume the deployer role" sts:AssumeRole "arn:aws:iam::$ACCOUNT:role/fluidbox-cloud/fluidbox-cloud-deployer"
sim operator allowed "terraform state write (BACKEND runs as operator)" s3:PutObject "arn:aws:s3:::fluidbox-cloud-tfstate-$ACCOUNT/platform.tfstate"
sim operator allowed "state lockfile write" s3:PutObject "arn:aws:s3:::fluidbox-cloud-tfstate-$ACCOUNT/platform.tfstate.tflock"
sim operator allowed "state bucket list" s3:ListBucket "arn:aws:s3:::fluidbox-cloud-tfstate-$ACCOUNT"
sim operator allowed "kubeconfig bootstrap" eks:DescribeCluster "arn:aws:eks:$REGION:$ACCOUNT:cluster/fluidbox-cloud"
sim operator denied "build infrastructure directly" ec2:CreateVpc "*"
sim operator denied "create an EKS cluster directly" eks:CreateCluster "arn:aws:eks:$REGION:$ACCOUNT:cluster/rogue"
sim operator denied "read the CloudTrail bucket" s3:GetObject "arn:aws:s3:::fluidbox-cloud-trail-$ACCOUNT/AWSLogs/x"
sim operator denied "escalate its own privileges" iam:AttachUserPolicy "arn:aws:iam::$ACCOUNT:user/fluidbox-cloud/fluidbox-operator"

{
  echo "# IAM policy simulation — deployer + operator"
  echo
  echo "Run $(date -u +%FT%TZ) by \`scripts/cloud/iam-simulate.sh\`."
  echo "Policies extracted from a live \`terraform plan\` (no fixture to drift),"
  echo "evaluated with \`aws iam simulate-custom-policy\` — a READ-ONLY API call."
  echo "Nothing was created."
  echo
  echo "Result: **$PASS passed, $FAILN failed**."
  echo
  echo "| case | action | expected | AWS decision |"
  echo "|---|---|---|---|"
  cat "$WORK/rows.md"
  echo
  echo "The negative cases matter as much as the positive ones: they are what"
  echo "prove the scoping actually scopes in a SHARED account, rather than the"
  echo "policy merely looking narrow. In particular the deployer cannot touch"
  echo "another project's roles, buckets or parameters, cannot pass a role to an"
  echo "arbitrary service, and cannot operate outside the pinned region."
} > "$OUT"

say "verdict"
echo "  PASS=$PASS FAIL=$FAILN   report: $OUT"
[ "$FAILN" -eq 0 ] \
  && ok "IAM policies grant exactly what the applies need, and refuse what they must" \
  || fail "IAM gaps found — fix bootstrap/iam.tf BEFORE the platform apply"
exit $((FAILN > 0))
