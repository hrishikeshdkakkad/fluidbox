#!/usr/bin/env bash
# Shared helpers for the fluidbox-cloud operator scripts. Source, don't run.

# shellcheck disable=SC2034  # BOLD/DIM are for the scripts that source this
BOLD=$'\033[1m'; DIM=$'\033[2m'; RED=$'\033[1;31m'; GREEN=$'\033[1;32m'
YELLOW=$'\033[1;33m'; CYAN=$'\033[1;36m'; RESET=$'\033[0m'
say()  { printf "\n%s== %s ==%s\n" "$CYAN" "$1" "$RESET"; }
ok()   { printf "  %s✓%s %s\n" "$GREEN" "$RESET" "$1"; }
warn() { printf "  %s⚠%s %s\n" "$YELLOW" "$RESET" "$1"; }
fail() { printf "  %s✗ %s%s\n" "$RED" "$1" "$RESET"; }
die()  { fail "$1"; shift || true; for l in "$@"; do printf "    %s\n" "$l"; done; exit 1; }

CLOUD_REGION="${CLOUD_REGION:-us-east-1}"
CLOUD_CLUSTER="${CLOUD_CLUSTER:-fluidbox-cloud}"
CLOUD_NS="${CLOUD_NS:-fluidbox}"
CLOUD_SANDBOX_NS="${CLOUD_SANDBOX_NS:-fluidbox-sandboxes}"
DEPLOYER_ROLE_ARN="${DEPLOYER_ROLE_ARN:-arn:aws:iam::471112572248:role/fluidbox-cloud/fluidbox-cloud-deployer}"
KUBECTX="${KUBECTX:-fluidbox-cloud}"

# Refuse root for anything except the bootstrap ceremony.
require_non_root() {
  local arn
  arn=$(aws sts get-caller-identity --query Arn --output text 2>/dev/null) \
    || die "aws credentials unavailable" "expected AWS_PROFILE=fluidbox-deployer (or -operator)"
  case "$arn" in
    *:root) die "refusing to run as the account ROOT identity" \
      "the M1.0 gate retired root for everything except the bootstrap ceremony" \
      "use: AWS_PROFILE=fluidbox-deployer $0" ;;
  esac
  ok "aws identity: $arn"
}

# Ensure a kubeconfig context for the cloud cluster exists and is selected.
ensure_kubeconfig() {
  if ! kubectl config get-contexts -o name 2>/dev/null | grep -qx "$KUBECTX"; then
    aws eks update-kubeconfig --name "$CLOUD_CLUSTER" --region "$CLOUD_REGION" \
      --role-arn "$DEPLOYER_ROLE_ARN" --alias "$KUBECTX" >/dev/null \
      || die "could not build kubeconfig for $CLOUD_CLUSTER"
  fi
  kubectl config use-context "$KUBECTX" >/dev/null || die "could not select context $KUBECTX"
  ok "kubectl context: $KUBECTX"
}

# Evidence directory helper: scripts append their proof artifacts here.
evidence_dir() {
  local name="$1" dir
  dir="docs/reviews/$(date +%Y-%m-%d)-${name}"
  mkdir -p "$dir"
  printf "%s" "$dir"
}
