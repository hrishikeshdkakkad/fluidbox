#!/usr/bin/env bash
# The out-of-band secrets, in one command.
#
# Terraform creates every secret in Secret Manager but deliberately never sees
# the values of the ones that come from OUTSIDE the project (model-provider keys,
# the IdP client secret). Those versions are added here - and only here - so
# the sequence a new operator follows is: apply the platform stack, run this,
# deploy. Nothing is typed twice, nothing is pasted into a values file, and no
# value is ever printed.
#
#   scripts/cloud/gcp-secrets.sh                         # report status only
#   scripts/cloud/gcp-secrets.sh --from-env-file .env    # add versions from a dotenv
#   OPENAI_API_KEY=... scripts/cloud/gcp-secrets.sh      # add versions from the environment
#   scripts/cloud/gcp-secrets.sh --prompt                # ask, with hidden input
#
# For each secret with a value on hand it adds a version - refusing an EMPTY
# value up front, because `gcloud secrets versions add` reports that as a bare
# "Secret Payload cannot be empty" that hides which variable was unset. A value
# identical to the current version is skipped, so re-running is free.
#
# Provider keys are read by the LiteLLM gateway at START, so after adding one
# this also asks the External Secrets operator to sync now and restarts the
# gateway Deployment (only when the cluster is reachable; otherwise it says so).
#
# Environment:
#   GCP_PROJECT   (default fluidbox-506603)     NAMESPACE  (default fluidbox)
#   RELEASE       (default fluidbox)

set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
# shellcheck source=scripts/cloud/lib.sh
. scripts/cloud/lib.sh

PROJECT="${GCP_PROJECT:-fluidbox-506603}"
NS="${NAMESPACE:-fluidbox}"
RELEASE="${RELEASE:-fluidbox}"

# secret id | env var | what it is | provider key? (restart the gateway)
SECRETS=(
  "anthropic-api-key|ANTHROPIC_API_KEY|Anthropic key for the LiteLLM gateway|yes"
  "openai-api-key|OPENAI_API_KEY|OpenAI key for the LiteLLM gateway (the codex harness)|yes"
  "auth0-client-secret|AUTH0_CLIENT_SECRET|OIDC client secret for the org IdP|no"
)

ENV_FILE=""; PROMPT=0
while [ $# -gt 0 ]; do
  case "$1" in
    --from-env-file) ENV_FILE="${2:-}"; shift 2;;
    --prompt) PROMPT=1; shift;;
    -h|--help) sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
    *) die "unknown argument: $1";;
  esac
done
if [ -n "$ENV_FILE" ]; then
  [ -r "$ENV_FILE" ] || die "cannot read $ENV_FILE"
  # Only the variables we know; a dotenv can carry anything.
  for row in "${SECRETS[@]}"; do
    var="$(cut -d'|' -f2 <<<"$row")"
    val="$(grep -E "^${var}=" "$ENV_FILE" | head -1 | cut -d= -f2- | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//")"
    [ -n "$val" ] && export "$var=$val"
  done
fi

command -v gcloud >/dev/null || die "gcloud not on PATH"
gcloud secrets list --project "$PROJECT" --format='value(name)' >/dev/null 2>&1 \
  || die "cannot list secrets in $PROJECT" "run scripts/cloud/gcp-reauth.sh, or check the project id"

# The current version's fingerprint, so an identical re-add is a no-op. Never
# the value: sha256 of it, and only the first 12 hex.
fingerprint() { gcloud secrets versions access latest --secret="$1" --project "$PROJECT" 2>/dev/null | shasum -a 256 | cut -c1-12; }

say "Out-of-band secrets in $PROJECT"
ADDED_PROVIDER=0; MISSING=0
for row in "${SECRETS[@]}"; do
  IFS='|' read -r id var desc provider <<<"$row"
  if ! gcloud secrets describe "$id" --project "$PROJECT" >/dev/null 2>&1; then
    fail "$id: not declared - apply the platform stack first"; MISSING=$((MISSING+1)); continue
  fi
  n="$(gcloud secrets versions list "$id" --project "$PROJECT" --filter='state=ENABLED' --format='value(name)' 2>/dev/null | wc -l | tr -d ' ')"
  val="${!var:-}"
  if [ -z "$val" ] && [ "$PROMPT" = 1 ] && [ -t 0 ]; then
    printf '  %s (%s) - paste to add, Enter to skip: ' "$id" "$desc"
    IFS= read -rs val; printf '\n'
  fi
  if [ -z "$val" ]; then
    if [ "$n" -gt 0 ]; then ok "$id: $n version(s) present ($var not given; unchanged)"
    else warn "$id: NO version yet - $desc. Set $var (or --from-env-file/--prompt) to add it"; MISSING=$((MISSING+1)); fi
    continue
  fi
  new_fp="$(printf '%s' "$val" | shasum -a 256 | cut -c1-12)"
  if [ "$n" -gt 0 ] && [ "$(fingerprint "$id")" = "$new_fp" ]; then
    ok "$id: current version already matches $var (fingerprint $new_fp)"; continue
  fi
  if printf '%s' "$val" | gcloud secrets versions add "$id" --data-file=- --project "$PROJECT" >/dev/null 2>&1; then
    ok "$id: version added from $var (fingerprint $new_fp)"
    [ "$provider" = yes ] && ADDED_PROVIDER=1
  else
    fail "$id: gcloud refused the version"; MISSING=$((MISSING+1))
  fi
done

if [ "$ADDED_PROVIDER" = 1 ]; then
  say "Rolling the gateway onto the new provider key"
  if kubectl -n "$NS" get externalsecret >/dev/null 2>&1; then
    # ESO's supported "sync now" is this annotation; refreshInterval is 1h.
    for es in $(kubectl -n "$NS" get externalsecret -o name 2>/dev/null); do
      kubectl -n "$NS" annotate "$es" force-sync="$(date +%s)" --overwrite >/dev/null 2>&1 && ok "synced $es"
    done
    sleep 5
    kubectl -n "$NS" rollout restart "deploy/${RELEASE}-litellm" >/dev/null 2>&1 \
      && kubectl -n "$NS" rollout status "deploy/${RELEASE}-litellm" --timeout=180s >/dev/null 2>&1 \
      && ok "gateway restarted with the new key" \
      || warn "gateway restart did not complete; check: kubectl -n $NS rollout status deploy/${RELEASE}-litellm"
  else
    warn "cluster not reachable from here - after deploying, restart the gateway once: kubectl -n $NS rollout restart deploy/${RELEASE}-litellm"
  fi
fi

[ "$MISSING" -eq 0 ] && { echo; ok "every out-of-band secret has a version"; exit 0; }
echo; warn "$MISSING secret(s) still need attention (see above)"; exit 1
