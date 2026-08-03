#!/usr/bin/env bash
# Creates the two out-of-band Kubernetes Secrets the app stack references —
# NEVER through Terraform, so no secret value can land in state (PLAN rev 3
# §P0). Idempotent: re-running preserves existing generated values unless
# ROTATE=1.
#
# Inputs (env):
#   FLUIDBOX_CLOUD_DATABASE_URL          Neon DIRECT (non-pooler) URL for the app DB   [required]
#   FLUIDBOX_CLOUD_LITELLM_DATABASE_URL  small dedicated LiteLLM DB URL                [required]
#   FLUIDBOX_CLOUD_ANTHROPIC_API_KEY     model key for LiteLLM                         [required]
#   FLUIDBOX_CLOUD_ADMIN_TOKEN / _CREDENTIAL_KEY / _LITELLM_MASTER_KEY  [optional: generated]
#
# Generated values are ALSO written to SSM SecureString under /fluidbox/cloud/*
# — losing FLUIDBOX_CREDENTIAL_KEY orphans sealed credentials and losing the
# admin token locks you out of /v1/admin, so they must exist somewhere durable
# that is not this laptop. (The KMS KEK is the *other* custody root; it lives
# in KMS and never leaves it.)
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.." || exit 1
. scripts/cloud/lib.sh

require_non_root
ensure_kubeconfig

: "${FLUIDBOX_CLOUD_DATABASE_URL:?set FLUIDBOX_CLOUD_DATABASE_URL (Neon DIRECT non-pooler URL — pgbouncer breaks sqlx + LISTEN/NOTIFY)}"
: "${FLUIDBOX_CLOUD_LITELLM_DATABASE_URL:?set FLUIDBOX_CLOUD_LITELLM_DATABASE_URL (dedicated small DB; NEVER the app DB)}"
: "${FLUIDBOX_CLOUD_ANTHROPIC_API_KEY:?set FLUIDBOX_CLOUD_ANTHROPIC_API_KEY}"

case "$FLUIDBOX_CLOUD_DATABASE_URL" in
  *-pooler*) die "DATABASE_URL looks like a POOLER endpoint" "use the DIRECT Neon connection string (CLAUDE.md gotcha: PgBouncer transaction mode breaks sqlx prepared statements and PgListener)";;
esac

ssm_get() { aws ssm get-parameter --with-decryption --name "$1" --query Parameter.Value --output text 2>/dev/null || true; }
ssm_put() { aws ssm put-parameter --name "$1" --type SecureString --value "$2" --overwrite >/dev/null; }

# Reuse (SSM), else generate. ROTATE=1 forces regeneration.
resolve() { # resolve <env-value> <ssm-path> <generator...>
  local envv="$1" path="$2"; shift 2
  if [ -n "$envv" ]; then printf "%s" "$envv"; return; fi
  if [ "${ROTATE:-0}" != "1" ]; then
    local existing; existing=$(ssm_get "$path")
    if [ -n "$existing" ] && [ "$existing" != "None" ]; then printf "%s" "$existing"; return; fi
  fi
  "$@"
}
gen_hex32() { openssl rand -hex 32; }
gen_token() { printf "fbx_admin_%s" "$(openssl rand -hex 24)"; }
gen_sk()    { printf "sk-litellm-%s" "$(openssl rand -hex 24)"; }

ADMIN_TOKEN=$(resolve "${FLUIDBOX_CLOUD_ADMIN_TOKEN:-}"       /fluidbox/cloud/admin-token        gen_token)
CRED_KEY=$(resolve    "${FLUIDBOX_CLOUD_CREDENTIAL_KEY:-}"    /fluidbox/cloud/credential-key     gen_hex32)
LITELLM_KEY=$(resolve "${FLUIDBOX_CLOUD_LITELLM_MASTER_KEY:-}" /fluidbox/cloud/litellm-master-key gen_sk)

say "SSM custody (SecureString, /fluidbox/cloud/*)"
ssm_put /fluidbox/cloud/admin-token        "$ADMIN_TOKEN"
ssm_put /fluidbox/cloud/credential-key     "$CRED_KEY"
ssm_put /fluidbox/cloud/litellm-master-key "$LITELLM_KEY"
ok "admin-token, credential-key, litellm-master-key recorded (values not printed)"

say "kubernetes secrets (namespace $CLOUD_NS)"
kubectl get namespace "$CLOUD_NS" >/dev/null 2>&1 || kubectl create namespace "$CLOUD_NS" >/dev/null
kubectl create secret generic fluidbox-secrets -n "$CLOUD_NS" \
  --from-literal=DATABASE_URL="$FLUIDBOX_CLOUD_DATABASE_URL" \
  --from-literal=FLUIDBOX_ADMIN_TOKEN="$ADMIN_TOKEN" \
  --from-literal=FLUIDBOX_CREDENTIAL_KEY="$CRED_KEY" \
  --from-literal=LITELLM_MASTER_KEY="$LITELLM_KEY" \
  --from-literal=ANTHROPIC_API_KEY="$FLUIDBOX_CLOUD_ANTHROPIC_API_KEY" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null
ok "fluidbox-secrets applied"

kubectl create secret generic fluidbox-litellm-db -n "$CLOUD_NS" \
  --from-literal=DATABASE_URL="$FLUIDBOX_CLOUD_LITELLM_DATABASE_URL" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null
ok "fluidbox-litellm-db applied"

say "done"
ok "app stack may now apply (scripts/cloud/deploy-app.sh)"
echo "  admin token for operator API calls:  aws ssm get-parameter --with-decryption --name /fluidbox/cloud/admin-token"
