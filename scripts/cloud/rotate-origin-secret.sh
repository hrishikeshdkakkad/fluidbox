#!/usr/bin/env bash
# Rotates the CloudFront→ALB origin secret header WITHOUT ever putting the
# value in Terraform state:
#
#   1. generate a new value; record it in SSM SecureString
#   2. Ingress conditions annotation accepts OLD+NEW (overlap window)
#   3. CloudFront origin custom header flips to NEW (wait for Deployed)
#   4. Ingress annotation narrows to NEW only
#   5. verify: via-CloudFront 200, direct-ALB refused
#
# helm upgrades preserve the annotation (three-way merge; the chart's values
# never set it), so rotation is orthogonal to deploys. MUST be run once right
# after the edge stack's first apply — until then the distribution carries the
# Terraform placeholder and the Ingress has no header rule at all (the ALB SG
# still confines traffic to CloudFront's origin-facing range, so the gap is
# "any CloudFront distribution", not "the internet").
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.." || exit 1
. scripts/cloud/lib.sh

command -v jq >/dev/null || die "jq required"

HEADER_NAME="x-fluidbox-origin-auth"
ANNOT_KEY="alb.ingress.kubernetes.io/conditions.fluidbox-server"
INGRESS="fluidbox-server"

# Resolve WHICH distribution to rotate before any remote setup. Rotating
# against an unknown target is unrecoverable operator confusion, and a
# kubeconfig failure here would obscure the actual problem.
say "resolve edge identifiers"
DIST_ID="${DIST_ID:-$(cd deploy/cloud/terraform/edge && terraform output -raw distribution_id 2>/dev/null)}" \
  || true
[ -n "${DIST_ID:-}" ] || die "distribution id unknown" "apply the edge stack first, or pass DIST_ID=…"

require_non_root
ensure_kubeconfig
CF_DOMAIN=$(aws cloudfront get-distribution --id "$DIST_ID" --query 'Distribution.DomainName' --output text)
ALB_ARN=$(aws resourcegroupstaggingapi get-resources \
  --tag-filters "Key=ingress.k8s.aws/stack,Values=${CLOUD_NS}/${INGRESS}" \
  --resource-type-filters elasticloadbalancing:loadbalancer \
  --query 'ResourceTagMappingList[0].ResourceARN' --output text)
[ "$ALB_ARN" != "None" ] || die "ALB not found by controller tags"
ALB_DNS=$(aws elbv2 describe-load-balancers --load-balancer-arns "$ALB_ARN" --query 'LoadBalancers[0].DNSName' --output text)
ok "distribution $DIST_ID ($CF_DOMAIN) → $ALB_DNS"

NEW=$(openssl rand -hex 24)
OLD=$(aws ssm get-parameter --with-decryption --name /fluidbox/cloud/origin-header \
  --query Parameter.Value --output text 2>/dev/null || true)
[ "$OLD" = "None" ] && OLD=""

annotate() { # annotate <json-values-array>
  kubectl annotate ingress "$INGRESS" -n "$CLOUD_NS" --overwrite \
    "${ANNOT_KEY}=[{\"field\":\"http-header\",\"httpHeaderConfig\":{\"httpHeaderName\":\"${HEADER_NAME}\",\"values\":$1}}]" >/dev/null
}

say "1/5 record new value in SSM"
aws ssm put-parameter --name /fluidbox/cloud/origin-header --type SecureString \
  --value "$NEW" --overwrite >/dev/null
ok "SSM /fluidbox/cloud/origin-header updated"

say "2/5 ingress accepts old+new"
if [ -n "$OLD" ]; then annotate "[\"$OLD\",\"$NEW\"]"; else annotate "[\"$NEW\"]"; fi
# The controller reconciles the listener rule; poll for the header condition.
LISTENER_ARN=$(aws elbv2 describe-listeners --load-balancer-arn "$ALB_ARN" --query 'Listeners[0].ListenerArn' --output text)
for i in $(seq 1 30); do
  if aws elbv2 describe-rules --listener-arn "$LISTENER_ARN" --output json \
      | jq -e --arg h "$HEADER_NAME" --arg v "$NEW" \
        '.Rules[].Conditions[]? | select(.Field=="http-header") | select(.HttpHeaderConfig.HttpHeaderName==($h)) | .HttpHeaderConfig.Values | index($v)' >/dev/null 2>&1; then
    ok "ALB rule carries the new value (after ~$((i*5))s)"; break
  fi
  [ "$i" = 30 ] && die "ALB rule never picked up the annotation (check aws-load-balancer-controller logs)"
  sleep 5
done

say "3/5 flip CloudFront origin header"
CFG=$(aws cloudfront get-distribution-config --id "$DIST_ID")
ETAG=$(printf '%s' "$CFG" | jq -r .ETag)
printf '%s' "$CFG" | jq --arg h "$HEADER_NAME" --arg v "$NEW" '
  .DistributionConfig
  | .Origins.Items[0].CustomHeaders = {Quantity: 1, Items: [{HeaderName: $h, HeaderValue: $v}]}
' > /tmp/fluidbox-cf-config.json
aws cloudfront update-distribution --id "$DIST_ID" --if-match "$ETAG" \
  --distribution-config file:///tmp/fluidbox-cf-config.json >/dev/null
rm -f /tmp/fluidbox-cf-config.json
echo "  waiting for the distribution to deploy (minutes)…"
aws cloudfront wait distribution-deployed --id "$DIST_ID"
ok "distribution deployed with the new header"

say "4/5 narrow ingress to new only"
annotate "[\"$NEW\"]"
sleep 10
ok "old value retired"

say "5/5 verify"
CODE_CF=$(curl -s -o /dev/null -w '%{http_code}' --max-time 30 "https://${CF_DOMAIN}/v1/health" || true)
[ "$CODE_CF" = "200" ] || die "via-CloudFront health check returned $CODE_CF (expected 200)"
ok "via CloudFront: 200"
CODE_ALB=$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 "http://${ALB_DNS}/v1/health" || true)
if [ "$CODE_ALB" = "200" ]; then
  die "DIRECT ALB request returned 200 — the origin lock is NOT holding"
fi
ok "direct ALB refused (got '${CODE_ALB:-timeout}' — SG and/or header rule)"
say "rotation complete"
