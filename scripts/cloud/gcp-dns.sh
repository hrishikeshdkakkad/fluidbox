#!/usr/bin/env bash
# Publish the control-plane hostname in Route 53, pointing at the reserved GCLB
# address from the platform Terraform stack.
#
# DNS lives in AWS while the load balancer lives in GCP, which is the reason the
# address is RESERVED rather than controller-allocated: a controller-allocated
# address changes whenever the Ingress is recreated, and the record that would
# have to follow it is in a different cloud with a different credential.
#
#   scripts/cloud/gcp-dns.sh              # apply
#   DRY_RUN=1 scripts/cloud/gcp-dns.sh    # print the change set and stop
#
# Environment:
#   CONTROL_HOST   default api.platform.fluidzero.ai
#   ZONE_NAME      default fluidzero.ai.
#   TTL            default 300
#   INGRESS_IP     default: read from `terraform output` in the platform stack

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

CONTROL_HOST="${CONTROL_HOST:-api.platform.fluidzero.ai}"
ZONE_NAME="${ZONE_NAME:-fluidzero.ai.}"
TTL="${TTL:-300}"

say()  { printf '\n\033[1m%s\033[0m\n' "$1"; }
die()  { printf '\033[31mERROR\033[0m %s\n' "$1" >&2; [ $# -gt 1 ] && printf '  %s\n' "$2" >&2; exit 1; }
ok()   { printf '  \033[32m✓\033[0m %s\n' "$1"; }

say "1. Resolve the load-balancer address"
IP="${INGRESS_IP:-}"
if [ -z "$IP" ]; then
  IP="$(terraform -chdir=deploy/cloud/gcp/platform output -raw ingress_ip 2>/dev/null || true)"
fi
[ -n "$IP" ] || die "no ingress address" \
  "run this after 'terraform apply' in deploy/cloud/gcp/platform, or set INGRESS_IP"
grep -qE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' <<<"$IP" || die "ingress_ip is not an IPv4 address: '$IP'"
ok "GCLB address: $IP"

say "2. Locate the hosted zone"
ZONE_ID="$(aws route53 list-hosted-zones \
  --query "HostedZones[?Name=='${ZONE_NAME}' && Config.PrivateZone==\`false\`].Id | [0]" \
  --output text 2>/dev/null | sed 's#/hostedzone/##')"
[ -n "$ZONE_ID" ] && [ "$ZONE_ID" != "None" ] || die "public hosted zone '$ZONE_NAME' not found"
ok "zone $ZONE_NAME -> $ZONE_ID"

say "3. Current state"
CUR="$(aws route53 list-resource-record-sets --hosted-zone-id "$ZONE_ID" \
  --query "ResourceRecordSets[?Name=='${CONTROL_HOST}.'].[Type,ResourceRecords[0].Value]" \
  --output text 2>/dev/null || true)"
if [ -n "$CUR" ]; then
  printf '  existing: %s\n' "$CUR"
  # A CNAME here would be a DIFFERENT record type, and UPSERT cannot convert
  # one type into another - it would fail with a confusing RRSet conflict.
  if grep -q CNAME <<<"$CUR"; then
    die "$CONTROL_HOST is currently a CNAME" \
        "delete it first: UPSERT cannot change a record's TYPE"
  fi
else
  ok "$CONTROL_HOST is unset (this will create it)"
fi

CHANGE=$(cat <<JSON
{
  "Comment": "fluidbox control plane -> GKE global load balancer",
  "Changes": [{
    "Action": "UPSERT",
    "ResourceRecordSet": {
      "Name": "${CONTROL_HOST}",
      "Type": "A",
      "TTL": ${TTL},
      "ResourceRecords": [{"Value": "${IP}"}]
    }
  }]
}
JSON
)

say "4. Change set"
printf '%s\n' "$CHANGE" | sed 's/^/  /'

if [ "${DRY_RUN:-}" = "1" ]; then
  say "DRY_RUN=1 — nothing applied"
  exit 0
fi

say "5. Apply"
ID=$(aws route53 change-resource-record-sets --hosted-zone-id "$ZONE_ID" \
  --change-batch "$CHANGE" --query 'ChangeInfo.Id' --output text)
ok "submitted $ID"
aws route53 wait resource-record-sets-changed --id "$ID" && ok "propagated to all Route 53 nameservers"

say "6. Verify"
# Query the zone's OWN nameserver: a resolver cache would happily serve the old
# answer and make this look like it had not worked.
NS=$(dig +short NS "${ZONE_NAME%.}" | head -1)
printf '  authoritative (%s): %s\n' "$NS" "$(dig +short "@${NS}" "$CONTROL_HOST" A | tr '\n' ' ')"
printf '  public resolver:     %s\n' "$(dig +short "$CONTROL_HOST" A | tr '\n' ' ')"

cat <<EOF

  Next: the GKE ManagedCertificate cannot finish provisioning until this record
  resolves publicly — Google validates by serving the challenge from the load
  balancer itself. Watch it with:

    kubectl -n fluidbox describe managedcertificate fluidbox-server

  Provisioning -> Active typically takes 15-60 minutes. A status of
  FailedNotVisible means the name still does not resolve to $IP.
EOF
