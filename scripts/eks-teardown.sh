#!/usr/bin/env bash
# MANDATORY teardown for the ephemeral EKS acceptance cluster. Idempotent and
# safe to run repeatedly (and even if the deploy half-failed). Everything is
# tagged fluidbox-ephemeral=true; eksctl tracks the cluster/VPC/NAT/nodegroup/
# IRSA in one CloudFormation stack, so `eksctl delete cluster` is the big
# hammer. This script also explicitly sweeps the resources that can linger.
set -uo pipefail
CLUSTER="${CLUSTER:-fluidbox-eks}"
REGION="${REGION:-us-east-1}"
NS="${NS:-fluidbox}"
SBNS="${SBNS:-fluidbox-sandboxes}"
say(){ printf "\n\033[1;36m== %s ==\033[0m\n" "$1"; }

say "1. helm uninstall + delete namespaces (frees Service LBs + PVC EBS volumes)"
helm uninstall fluidbox -n "$NS" 2>/dev/null || true
kubectl delete ns "$NS" "$SBNS" --wait=false 2>/dev/null || true
# Give the CSI driver + cloud controller a moment to delete EBS + LBs before
# eksctl tears down the VPC (orphaned ENIs otherwise block VPC deletion).
sleep 30

say "2. explicit LB sweep (Service-created NLB/CLB tagged with the cluster)"
for lb in $(aws elbv2 describe-load-balancers --region "$REGION" \
    --query "LoadBalancers[?contains(LoadBalancerName,'$CLUSTER')].LoadBalancerArn" --output text 2>/dev/null); do
  echo "deleting LB $lb"; aws elbv2 delete-load-balancer --region "$REGION" --load-balancer-arn "$lb" 2>/dev/null || true
done
# Classic ELBs tagged kubernetes.io/cluster/<cluster>
for clb in $(aws elb describe-load-balancers --region "$REGION" \
    --query "LoadBalancerDescriptions[].LoadBalancerName" --output text 2>/dev/null); do
  tags=$(aws elb describe-tags --region "$REGION" --load-balancer-names "$clb" --query "TagDescriptions[].Tags[?Key=='kubernetes.io/cluster/$CLUSTER'].Value" --output text 2>/dev/null)
  [ -n "$tags" ] && { echo "deleting classic ELB $clb"; aws elb delete-load-balancer --region "$REGION" --load-balancer-name "$clb" 2>/dev/null || true; }
done

say "3. eksctl delete cluster (nodegroup + control plane + VPC + NAT + IRSA)"
eksctl delete cluster --name "$CLUSTER" --region "$REGION" --disable-nodegroup-eviction --wait 2>&1 | tail -20 || true

say "4. explicit EBS sweep (any volume tagged with the cluster, e.g. archive PVC)"
for vol in $(aws ec2 describe-volumes --region "$REGION" \
    --filters "Name=tag:kubernetes.io/cluster/$CLUSTER,Values=owned,shared" \
    --query "Volumes[].VolumeId" --output text 2>/dev/null); do
  echo "deleting EBS $vol"; aws ec2 delete-volume --region "$REGION" --volume-id "$vol" 2>/dev/null || true
done

say "5. delete ECR repos"
for repo in fluidbox-server fluidbox-workspaced fluidbox-sandbox-runner; do
  aws ecr delete-repository --region "$REGION" --repository-name "$repo" --force 2>/dev/null && echo "deleted ECR $repo" || true
done

say "6. AUDIT — everything below must be EMPTY / clean"
echo "-- resources tagged fluidbox-ephemeral (should be empty):"
aws resourcegroupstaggingapi get-resources --region "$REGION" \
  --tag-filters "Key=fluidbox-ephemeral,Values=true" \
  --query "ResourceTagMappingList[].ResourceARN" --output text 2>/dev/null || true
echo "-- CloudFormation stacks named eksctl-$CLUSTER-* (should be empty):"
aws cloudformation list-stacks --region "$REGION" \
  --stack-status-filter CREATE_COMPLETE UPDATE_COMPLETE DELETE_FAILED \
  --query "StackSummaries[?contains(StackName,'$CLUSTER')].StackName" --output text 2>/dev/null || true
echo "-- NAT gateways (available):"; aws ec2 describe-nat-gateways --region "$REGION" --filter "Name=state,Values=available" --query "NatGateways[].NatGatewayId" --output text 2>/dev/null || true
echo "-- EBS volumes (available/in-use tagged with cluster):"; aws ec2 describe-volumes --region "$REGION" --filters "Name=tag:kubernetes.io/cluster/$CLUSTER,Values=owned,shared" --query "Volumes[].VolumeId" --output text 2>/dev/null || true
echo "-- unattached EIPs:"; aws ec2 describe-addresses --region "$REGION" --query "Addresses[?AssociationId==null].AllocationId" --output text 2>/dev/null || true
echo "-- load balancers named *$CLUSTER*:"; aws elbv2 describe-load-balancers --region "$REGION" --query "LoadBalancers[?contains(LoadBalancerName,'$CLUSTER')].LoadBalancerName" --output text 2>/dev/null || true
say "teardown complete — confirm the audit lists above are empty"
