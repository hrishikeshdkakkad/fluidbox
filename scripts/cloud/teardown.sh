#!/usr/bin/env bash
# Full environment teardown, in the ONLY order that works, plus the sweeps for
# the two RECURRING EKS-lifecycle leaks documented in
# docs/reviews/2026-07-22-eks-acceptance-phase-f.md:
#   leak 1: a detached VPC-CNI ENI (GC race) holds a subnet → VPC delete fails
#   leak 2: the EKS-created cluster SG (eks-cluster-sg-<cluster>-*) lives
#           OUTSIDE any Terraform/CFN resource set and holds the VPC
#
# Each terraform destroy prompts interactively — that prompt is the per-action
# user approval. Bootstrap (budgets/trail/IAM/state) is NOT destroyed here on
# purpose; guardrails outlive environments.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.." || exit 1
. scripts/cloud/lib.sh

require_non_root

say "1/5 edge stack (CloudFront) destroy"
(cd deploy/cloud/terraform/edge && terraform init -input=false >/dev/null && terraform destroy) || warn "edge destroy incomplete (continuing; re-run after fixing)"

say "2/5 app stack destroy (helm uninstall → controller deletes the ALB)"
(cd deploy/cloud/terraform/app && terraform init -input=false >/dev/null && terraform destroy) || warn "app destroy incomplete"

echo "  waiting for the controller-created ALB to disappear (frees the frontend SG + subnets)…"
for i in $(seq 1 30); do
  ALB=$(aws resourcegroupstaggingapi get-resources \
    --tag-filters "Key=elbv2.k8s.aws/cluster,Values=$CLOUD_CLUSTER" \
    --resource-type-filters elasticloadbalancing:loadbalancer \
    --query 'ResourceTagMappingList[0].ResourceARN' --output text 2>/dev/null || true)
  [ -z "$ALB" ] || [ "$ALB" = "None" ] && { ok "ALB gone"; break; }
  [ "$i" = 30 ] && warn "ALB still present after 5m — platform destroy may fail on the VPC; delete it manually"
  sleep 10
done

say "3/5 platform stack destroy (EKS + VPC — the long one)"
VPC_ID=$(cd deploy/cloud/terraform/platform && terraform output -raw vpc_id 2>/dev/null || true)
(cd deploy/cloud/terraform/platform && terraform init -input=false >/dev/null && terraform destroy) || warn "platform destroy incomplete — the sweeps below often unblock a retry"

say "4/5 leak sweeps (safe to re-run; no-ops when clean)"
if [ -n "$VPC_ID" ]; then
  # Leak 1: available (detached) ENIs still holding the subnets.
  for eni in $(aws ec2 describe-network-interfaces \
      --filters "Name=vpc-id,Values=$VPC_ID" "Name=status,Values=available" \
      --query 'NetworkInterfaces[].NetworkInterfaceId' --output text 2>/dev/null); do
    echo "  deleting leaked ENI $eni"
    aws ec2 delete-network-interface --network-interface-id "$eni" 2>/dev/null || true
  done
  # Leak 2: the EKS-created cluster SG outside the Terraform resource set.
  for sg in $(aws ec2 describe-security-groups \
      --filters "Name=vpc-id,Values=$VPC_ID" "Name=group-name,Values=eks-cluster-sg-${CLOUD_CLUSTER}-*" \
      --query 'SecurityGroups[].GroupId' --output text 2>/dev/null); do
    echo "  deleting EKS-created cluster SG $sg"
    aws ec2 delete-security-group --group-id "$sg" 2>/dev/null || true
  done
  # Tagged EBS leftovers (archive PVC volumes the CSI driver may not have reaped).
  for vol in $(aws ec2 describe-volumes \
      --filters "Name=tag:kubernetes.io/cluster/${CLOUD_CLUSTER},Values=owned,shared" "Name=status,Values=available" \
      --query 'Volumes[].VolumeId' --output text 2>/dev/null); do
    echo "  deleting leftover EBS $vol"
    aws ec2 delete-volume --volume-id "$vol" 2>/dev/null || true
  done
  ok "sweeps done — if platform destroy failed above, re-run it now"
else
  warn "vpc id unknown (platform outputs gone?) — sweeps skipped"
fi

say "5/5 orphan audit"
LEFT=0
aws eks list-clusters --query 'clusters' --output text | grep -q "$CLOUD_CLUSTER" && { fail "cluster still exists"; LEFT=1; } || ok "no cluster"
CNT=$(aws ec2 describe-network-interfaces --filters "Name=status,Values=available" --query 'length(NetworkInterfaces)' --output text 2>/dev/null || echo 0)
[ "$CNT" = "0" ] && ok "no available ENIs account-wide" || warn "$CNT available ENI(s) remain (verify none are ours)"
[ "$LEFT" = "0" ] && ok "teardown complete — remember the kubeconfig context: kubectl config delete-context $KUBECTX" \
  || die "teardown left resources — re-run after inspecting"
