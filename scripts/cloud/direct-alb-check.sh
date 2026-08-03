#!/usr/bin/env bash
# §9 criterion 12 evidence: direct ALB requests are rejected; the CloudFront
# path serves. Records the transcript into the evidence dir.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.." || exit 1
. scripts/cloud/lib.sh

CF_DOMAIN="${CF_DOMAIN:-$(cd deploy/cloud/terraform/edge && terraform output -raw cloudfront_domain 2>/dev/null)}"
ALB_DNS="${ALB_DNS:-$(cd deploy/cloud/terraform/edge && terraform output -raw alb_dns_name 2>/dev/null)}"
[ -n "$CF_DOMAIN" ] && [ -n "$ALB_DNS" ] || die "edge stack outputs unavailable (apply edge first or set CF_DOMAIN/ALB_DNS)"

EV=$(evidence_dir cloud-m1-edge-lock)
LOG="$EV/direct-alb-check.txt"
{
  echo "# direct-ALB refusal check — $(date -u +%FT%TZ)"
  echo "cloudfront: $CF_DOMAIN"
  echo "alb:        $ALB_DNS"
} > "$LOG"

say "via CloudFront (must serve)"
CF_CODE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 30 "https://${CF_DOMAIN}/v1/health" || echo "curl-fail")
echo "GET https://${CF_DOMAIN}/v1/health -> $CF_CODE" | tee -a "$LOG"
[ "$CF_CODE" = "200" ] && ok "cloudfront path serves" || fail "cloudfront path returned $CF_CODE"

say "direct ALB, no header (must be refused)"
ALB_CODE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 "http://${ALB_DNS}/v1/health" || echo "timeout/refused")
echo "GET http://${ALB_DNS}/v1/health -> $ALB_CODE" | tee -a "$LOG"

say "direct ALB, forged header (simulates a foreign CloudFront distribution WITHOUT the secret)"
FORGED_CODE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 -H 'x-fluidbox-origin-auth: wrong-value' "http://${ALB_DNS}/v1/health" || echo "timeout/refused")
echo "GET http://${ALB_DNS}/v1/health (bad header) -> $FORGED_CODE" | tee -a "$LOG"

VERDICT=PASS
[ "$CF_CODE" = "200" ] || VERDICT=FAIL
case "$ALB_CODE" in 200) VERDICT=FAIL;; esac
case "$FORGED_CODE" in 200) VERDICT=FAIL;; esac
echo "verdict: $VERDICT" | tee -a "$LOG"
[ "$VERDICT" = "PASS" ] && ok "edge lock holds (evidence: $LOG)" || die "edge lock FAILED — see $LOG" \
  "note: from a non-CloudFront IP the SG normally makes both direct probes time out; a 403/404 means the header rule did the refusing. Any 200 is a failure."
