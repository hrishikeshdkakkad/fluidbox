#!/usr/bin/env bash
# Order-enforcing wrapper for the app stack: proves the out-of-band Secrets
# exist BEFORE terraform runs (a missing secret otherwise surfaces as a
# 15-minute helm wait timeout). Terraform's own interactive approval prompt is
# the per-action user approval — this wrapper never passes -auto-approve.
#
#   AWS_PROFILE=fluidbox-operator scripts/cloud/deploy-app.sh
#
# OPERATOR profile, not deployer — this script ends in `terraform apply`, and
# the stack's provider assumes the deployer role itself, so the ambient
# identity must be the operator user that role trusts. (Terraform's S3 backend
# also runs as the ambient identity; it does not inherit the provider's
# assume_role.) Pure-script operations — verify-bootstrap, rotate-origin-secret,
# direct-alb-check, replay-on-cluster, idle-scaledown-watch, teardown — take
# the DEPLOYER profile instead, because they call AWS directly.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.." || exit 1
. scripts/cloud/lib.sh

require_non_root
ensure_kubeconfig

say "preflight: out-of-band secrets"
kubectl get secret fluidbox-secrets -n "$CLOUD_NS" >/dev/null 2>&1 \
  || die "fluidbox-secrets missing in $CLOUD_NS" "run scripts/cloud/make-secrets.sh first"
for key in DATABASE_URL FLUIDBOX_ADMIN_TOKEN FLUIDBOX_CREDENTIAL_KEY LITELLM_MASTER_KEY ANTHROPIC_API_KEY OPENAI_API_KEY; do
  kubectl get secret fluidbox-secrets -n "$CLOUD_NS" -o jsonpath="{.data.$key}" 2>/dev/null | grep -q . \
    || die "fluidbox-secrets is missing key $key" "re-run scripts/cloud/make-secrets.sh"
done
kubectl get secret fluidbox-litellm-db -n "$CLOUD_NS" >/dev/null 2>&1 \
  || die "fluidbox-litellm-db missing in $CLOUD_NS" "run scripts/cloud/make-secrets.sh first"
ok "both secrets present with required keys"

say "terraform (app stack) — review the plan; the apply prompt is YOUR per-action approval"
cd deploy/cloud/terraform/app
terraform init -input=false
terraform apply "$@"
