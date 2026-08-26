#!/usr/bin/env bash
# Restore local gcloud credentials for the GCP deployment, INTERACTIVELY.
#
# Why this script exists: `gcloud auth list` never contacts Google. It prints
# rows from a local file, so an account shows as ACTIVE even when its refresh
# token is dead. "Signed in" is a local fact; "usable" requires a live token
# exchange. This script forces that exchange and reports the truth.
#
# There are TWO independent credential stores and either can die alone:
#
#   1. The gcloud CLI store  - used by every `gcloud`/`kubectl` call.
#                              Proof of life: `gcloud auth print-access-token`.
#   2. Application Default   - used by client libraries, Terraform's Google
#      Credentials (ADC)       provider, and any script driving the REST APIs.
#                              Proof of life:
#                              `gcloud auth application-default print-access-token`.
#
# Run this from a REAL TERMINAL. Both logins open a browser and may issue a
# reauthentication challenge, which cannot be answered from a non-interactive
# process - that is the exact failure this repairs.
#
#   scripts/cloud/gcp-reauth.sh
#
# Environment:
#   GCP_PROJECT   project to target        (default fluidbox-506603)
#   GCP_ACCOUNT   account to sign in as    (default: the configured account)
#   SKIP_KUBE=1   skip fetching GKE credentials
#
# No token is ever printed. Checks redirect token output to /dev/null and
# report only the exit status.

set -uo pipefail

PROJECT="${GCP_PROJECT:-fluidbox-506603}"
CLUSTER="${GCP_CLUSTER:-fluidbox}"
ZONE="${GCP_ZONE:-us-central1-c}"   # zonal cluster: --zone, never --region
ADC_FILE="${CLOUDSDK_CONFIG:-$HOME/.config/gcloud}/application_default_credentials.json"

PASS=0; FAIL=0
ok()  { printf '  \033[32m✓\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
bad() { printf '  \033[31m✗\033[0m %s\n' "$1"; [ $# -gt 1 ] && printf '      %s\n' "$2"; FAIL=$((FAIL+1)); }
hdr() { printf '\n\033[1m%s\033[0m\n' "$1"; }

# --- preconditions -----------------------------------------------------------

command -v gcloud >/dev/null 2>&1 || { echo "gcloud not on PATH"; exit 1; }

if [ ! -t 0 ]; then
  cat >&2 <<'EOF'
This script must run on a terminal with a TTY. Both logins can raise a
reauthentication prompt, and a prompt with nowhere to go is the failure being
repaired. Open a normal terminal and run it there.
EOF
  exit 1
fi

ACCOUNT="${GCP_ACCOUNT:-$(gcloud config get account 2>/dev/null | tr -d '[:space:]')}"
if [ -z "$ACCOUNT" ] || [ "$ACCOUNT" = "(unset)" ]; then
  echo "No account configured. Re-run with GCP_ACCOUNT=you@example.com" >&2
  exit 1
fi

hdr "Target"
printf '  project  %s\n  account  %s\n  cluster  %s (zone %s)\n' \
  "$PROJECT" "$ACCOUNT" "$CLUSTER" "$ZONE"

hdr "Before"
if gcloud auth print-access-token >/dev/null 2>&1; then
  ok "CLI store already mints a token"
else
  bad "CLI store cannot mint a token" "$(gcloud auth print-access-token 2>&1 | head -1)"
fi
if gcloud auth application-default print-access-token >/dev/null 2>&1; then
  ok "ADC already mints a token"
else
  bad "ADC cannot mint a token" "$(gcloud auth application-default print-access-token 2>&1 | head -1)"
fi
PASS=0; FAIL=0   # the "before" section is a diagnosis, not a verdict

# --- login -------------------------------------------------------------------

hdr "1/2  CLI credential"
echo "  A browser will open. Choose $ACCOUNT - NOT a personal account."
gcloud auth login "$ACCOUNT" --force || { echo "CLI login failed" >&2; exit 1; }

hdr "2/2  Application Default Credentials"
echo "  A browser will open again. Choose the SAME account."
gcloud auth application-default login || { echo "ADC login failed" >&2; exit 1; }

gcloud config set account "$ACCOUNT" --quiet >/dev/null 2>&1
gcloud config set project "$PROJECT" --quiet >/dev/null 2>&1
gcloud auth application-default set-quota-project "$PROJECT" --quiet >/dev/null 2>&1

# --- proof of life -----------------------------------------------------------

hdr "Verification"

gcloud auth print-access-token >/dev/null 2>&1 \
  && ok "CLI store mints a token" \
  || bad "CLI store still cannot mint a token" "$(gcloud auth print-access-token 2>&1 | head -1)"

gcloud auth application-default print-access-token >/dev/null 2>&1 \
  && ok "ADC mints a token" \
  || bad "ADC still cannot mint a token" "$(gcloud auth application-default print-access-token 2>&1 | head -1)"

# The account picker is the trap: a browser logged into a personal account will
# happily hand back a credential with no access to this project. Compare, do
# not assume.
CLI_ACCOUNT="$(gcloud config get account 2>/dev/null | tr -d '[:space:]')"
[ "$CLI_ACCOUNT" = "$ACCOUNT" ] \
  && ok "CLI account is $ACCOUNT" \
  || bad "CLI account is $CLI_ACCOUNT, expected $ACCOUNT"

# The ADC file carries an `account` field, and reading it proves NOTHING:
# `gcloud auth application-default login` writes it EMPTY (only the
# `gcloud auth login --update-adc` path populates it), so a file-field check
# reports a wrong account for every correct login. Ask the token who it
# belongs to instead - authoritative, and the answer that actually catches a
# browser which handed back the wrong identity.
ADC_ACCOUNT="$(
  TOK="$(gcloud auth application-default print-access-token 2>/dev/null)"
  [ -n "$TOK" ] && curl -sf -m 15 -H "Authorization: Bearer $TOK" \
    https://www.googleapis.com/oauth2/v3/userinfo 2>/dev/null \
    | python3 -c 'import json,sys;print(json.load(sys.stdin).get("email",""))' 2>/dev/null
)"
if [ -z "$ADC_ACCOUNT" ]; then
  bad "could not resolve the ADC identity" "userinfo lookup failed - check connectivity"
elif [ "$ADC_ACCOUNT" = "$ACCOUNT" ]; then
  ok "ADC identity is $ACCOUNT (resolved from the token, not from a file field)"
else
  bad "ADC identity is $ADC_ACCOUNT, expected $ACCOUNT" \
      "The browser picked a different account. Re-run and choose $ACCOUNT."
fi

ADC_QUOTA="$(python3 -c "import json;print(json.load(open('$ADC_FILE')).get('quota_project_id',''))" 2>/dev/null)"
[ "$ADC_QUOTA" = "$PROJECT" ] \
  && ok "ADC quota project is $PROJECT" \
  || bad "ADC quota project is ${ADC_QUOTA:-<none>}, expected $PROJECT"

# A token that mints is not a token that is AUTHORIZED. Spend it on a real
# read against the real project.
if gcloud projects describe "$PROJECT" --format='value(projectId)' >/dev/null 2>&1; then
  ok "authorized on project $PROJECT"
else
  bad "not authorized on project $PROJECT" "$(gcloud projects describe "$PROJECT" 2>&1 | head -1)"
fi

# --- cluster access ----------------------------------------------------------

if [ "${SKIP_KUBE:-0}" = "1" ]; then
  printf '  \033[33m–\033[0m GKE credentials (SKIP_KUBE=1)\n'
else
  hdr "Cluster access"
  if gcloud container clusters get-credentials "$CLUSTER" \
       --zone "$ZONE" --project "$PROJECT" >/dev/null 2>&1; then
    ok "kubeconfig entry written for $CLUSTER"
    if kubectl get nodes >/dev/null 2>&1; then
      ok "kubectl reaches the API server ($(kubectl get nodes --no-headers 2>/dev/null | wc -l | tr -d ' ') node(s))"
    else
      bad "kubectl cannot reach the API server" "$(kubectl get nodes 2>&1 | head -1)"
    fi
  else
    bad "get-credentials failed" \
        "$(gcloud container clusters get-credentials "$CLUSTER" --zone "$ZONE" --project "$PROJECT" 2>&1 | head -1)"
  fi
fi

# --- verdict -----------------------------------------------------------------

printf '\n\033[1m%d passed, %d failed\033[0m\n' "$PASS" "$FAIL"
if [ "$FAIL" -eq 0 ]; then
  cat <<EOF

Credentials restored. Both stores mint tokens and the project answers.

Note: this repairs LOCAL access only. The production pipeline
(.github/workflows/deploy.yml) authenticates through Workload Identity
Federation and holds no long-lived credential, so deploys were never
affected by this expiry.
EOF
  exit 0
fi
exit 1
