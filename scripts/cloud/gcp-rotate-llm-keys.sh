#!/usr/bin/env bash
# Rotate tenants' LiteLLM virtual keys on the GCP deployment.
#
# Why this exists: in llm.keyMode "tenant" every model request rides a
# per-tenant virtual key, and that key's MODEL ALLOWLIST is fixed at mint.
# Widening llm.tenant.models and deploying changes what NEW keys get - every
# existing key keeps refusing the new models with
#   403 key not allowed to access model
# until it is rotated. Rotation mints a fresh key under the current allowlist,
# swaps it in, and retires the old one at LiteLLM. The key is never returned
# (the API answers {"rotated": true}) and never printed here.
#
#   scripts/cloud/gcp-rotate-llm-keys.sh              # every org
#   scripts/cloud/gcp-rotate-llm-keys.sh fluidzero    # named orgs only
#
# Environment:
#   CONTROL_HOST           control-plane origin  (default api.platform.fluidzero.ai)
#   FLUIDBOX_ADMIN_TOKEN   admin token; when unset it is read from Secret
#                          Manager (fluidbox-admin-token in GCP_PROJECT)
#   GCP_PROJECT            (default fluidbox-506603)
#
# Runs are unaffected mid-flight: the facade swaps the credential per request,
# and an in-flight stream completes on the key it started with.

set -uo pipefail

CONTROL_HOST="${CONTROL_HOST:-api.platform.fluidzero.ai}"
PROJECT="${GCP_PROJECT:-fluidbox-506603}"
API="https://$CONTROL_HOST"

TOKEN="${FLUIDBOX_ADMIN_TOKEN:-}"
if [ -z "$TOKEN" ]; then
  TOKEN="$(gcloud secrets versions access latest --secret=fluidbox-admin-token --project "$PROJECT" 2>/dev/null)" \
    || { echo "could not read fluidbox-admin-token from Secret Manager" >&2; exit 1; }
fi
[ -n "$TOKEN" ] || { echo "no admin token" >&2; exit 1; }

if [ $# -gt 0 ]; then
  SLUGS=("$@")
else
  mapfile -t SLUGS < <(curl -sf -m 15 -H "Authorization: Bearer $TOKEN" "$API/v1/admin/orgs" \
    | python3 -c 'import json,sys; [print(o["slug"]) for o in json.load(sys.stdin)["orgs"]]')
  [ ${#SLUGS[@]} -gt 0 ] || { echo "no orgs listed (auth or connectivity)" >&2; exit 1; }
fi

FAIL=0
for slug in "${SLUGS[@]}"; do
  out="$(curl -s -m 60 -o /dev/stderr -w '%{http_code}' -X POST \
          -H "Authorization: Bearer $TOKEN" "$API/v1/admin/orgs/$slug/llm-key/rotate" 2>/tmp/rotate.$$)"
  body="$(cat /tmp/rotate.$$ 2>/dev/null)"; rm -f /tmp/rotate.$$
  if [ "$out" = "200" ] && printf '%s' "$body" | grep -q '"rotated": *true'; then
    printf '  \033[32m✓\033[0m %s rotated\n' "$slug"
  else
    printf '  \033[31m✗\033[0m %s -> HTTP %s %s\n' "$slug" "$out" "$(printf '%s' "$body" | head -c 160)"
    FAIL=$((FAIL+1))
  fi
done
unset TOKEN
[ "$FAIL" -eq 0 ] && exit 0
echo "$FAIL rotation(s) failed" >&2; exit 1
