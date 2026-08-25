#!/usr/bin/env bash
# Register Auth0 as an org's OIDC issuer on the GCP deployment.
#
# A THIN WRAPPER, deliberately. scripts/cloud/auth0-idp-setup.sh already does
# the whole dance - conformance preflight against the issuer, idempotent app
# creation, registration through core's own LIVE discovery floor, migrate-vs-
# create, activation - and it was proven on the AWS deployment. Only two things
# in it are AWS-specific, and both are already environment overrides:
#
#   CLOUD_API              defaults to the CloudFront origin
#   FLUIDBOX_ADMIN_TOKEN   otherwise read from AWS SSM
#
# So the GCP variant is those two values plus the public URL, not a second copy
# of two hundred lines of OIDC logic that would drift.
#
#   scripts/cloud/gcp-auth0.sh <org-slug> [--with-drill-user <email>]
#   scripts/cloud/gcp-auth0.sh --promote <org-slug> <email>

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

PROJECT="${GCP_PROJECT:-fluidbox-506603}"

# The control plane's OWN origin, not the dashboard's. Admin calls are
# server-to-server: they carry a bearer token, need no cookie, and must not
# depend on the dashboard being deployed - or on Vercel's Attack Challenge
# Mode, which 429s every non-browser client.
export CLOUD_API="${CLOUD_API:-https://api.platform.fluidzero.ai}"

# The BROWSER-facing origin. This is what feeds the OAuth redirect_uri, so it
# must be the Vercel host: __Host- cookies are origin-locked and the callback
# has to land where the dashboard lives.
export FLUIDBOX_PUBLIC_URL="${FLUIDBOX_PUBLIC_URL:-https://platform.fluidzero.ai}"

export AUTH0_APP_NAME="${AUTH0_APP_NAME:-Fluidbox Platform (fluidzero.ai)}"

if [ -z "${FLUIDBOX_ADMIN_TOKEN:-}" ]; then
  FLUIDBOX_ADMIN_TOKEN="$(gcloud secrets versions access latest \
    --secret=fluidbox-admin-token --project "$PROJECT" 2>/dev/null)" || {
      echo "could not read fluidbox-admin-token from Secret Manager in $PROJECT" >&2
      echo "  (is the platform stack applied, and are you authenticated?)" >&2
      exit 1
    }
  export FLUIDBOX_ADMIN_TOKEN
fi

exec scripts/cloud/auth0-idp-setup.sh "$@"
