#!/usr/bin/env bash
# Failure-path smoke test for the operator toolkit.
#
# Every script here is run by a human under pressure — mid-incident, or at the
# end of a long apply. The question this answers is not "does it work" but
# "when a prerequisite is missing, does it stop immediately and say something
# ACTIONABLE, or does it hang, crash, or quietly do the wrong thing?"
#
# Each case deliberately removes one prerequisite and asserts:
#   * non-zero exit (never a silent success),
#   * a message containing an expected keyword,
#   * completion inside a short timeout (never a hang).
#
# Nothing here mutates AWS, Kubernetes, or any database.
#
#   scripts/cloud/guardrail-smoke.sh
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.." || exit 1
. scripts/cloud/lib.sh

EV=$(evidence_dir cloud-m1-readiness)
OUT="$EV/guardrail-smoke.md"
WORK="${SCRATCH:-/tmp/fluidbox-guardrail}"
mkdir -p "$WORK"
PASS=0; FAILN=0
: > "$WORK/rows.md"

case_() { # case_ <label> <expect-keyword> <timeout> <cmd...>
  local label="$1" want="$2" t="$3"; shift 3
  local out rc
  out=$(timeout "$t" env "$@" 2>&1); rc=$?
  local first; first=$(printf '%s' "$out" | grep -vE '^\s*$' | head -1 | sed 's/\x1b\[[0-9;]*m//g' | cut -c1-96)
  local verdict="FAIL"
  if [ "$rc" = "124" ]; then
    fail "$label — HUNG (no exit within ${t}s)"; FAILN=$((FAILN+1))
  elif [ "$rc" = "0" ]; then
    fail "$label — exited 0 despite a missing prerequisite (silent success)"; FAILN=$((FAILN+1))
  elif printf '%s' "$out" | grep -qi -- "$want"; then
    ok "$label — refused: ${first}"; PASS=$((PASS+1)); verdict="PASS"
  else
    fail "$label — exited $rc but never mentioned '$want': ${first}"; FAILN=$((FAILN+1))
  fi
  printf '| %s | `%s` | %s | %s |\n' "$label" "$want" "$verdict" "${first//|/\\|}" >> "$WORK/rows.md"
}

say "1. destructive scripts must refuse the ROOT identity"
# These currently run with the account root credentials, which is exactly the
# state the M1.0 ceremony exists to end. Nothing may proceed under them.
case_ "teardown refuses root"        "root"        30 scripts/cloud/teardown.sh
case_ "deploy-app refuses root"      "root"        30 scripts/cloud/deploy-app.sh
case_ "replay-on-cluster refuses root" "root"      30 scripts/cloud/replay-on-cluster.sh
# make-secrets validates its inputs before touching AWS (that ordering is
# deliberate), so its root refusal is only reachable with the inputs supplied.
case_ "make-secrets refuses root"    "root"        30 \
  FLUIDBOX_CLOUD_DATABASE_URL="postgres://u:p@ep-x.aws.neon.tech/db" \
  FLUIDBOX_CLOUD_LITELLM_DATABASE_URL="postgres://u:p@ep-y.aws.neon.tech/db" \
  FLUIDBOX_CLOUD_ANTHROPIC_API_KEY=sk-test \
  scripts/cloud/make-secrets.sh

# The input-validation guards sit BEHIND the identity check, which is the
# right order but makes them unreachable from here: this session holds root
# credentials, and the scripts correctly refuse those. A stub `aws` on PATH
# answers only `sts get-caller-identity` with a plausible non-root ARN, so the
# scripts proceed to the guard actually under test. It performs no AWS calls —
# any other subcommand exits non-zero.
STUB="$WORK/stub-bin"; mkdir -p "$STUB"
cat > "$STUB/aws" <<'STUBEOF'
#!/usr/bin/env bash
if [ "$1" = "sts" ] && [ "$2" = "get-caller-identity" ]; then
  echo "arn:aws:sts::471112572248:assumed-role/fluidbox-cloud-deployer/smoke"
  exit 0
fi
echo "stub aws: refusing '$*' (guardrail smoke test performs no AWS calls)" >&2
exit 1
STUBEOF
chmod +x "$STUB/aws"

say "2. missing inputs must be named, not guessed"
case_ "make-secrets names the missing DATABASE_URL" "FLUIDBOX_CLOUD_DATABASE_URL" 30 \
  PATH="$STUB:$PATH" scripts/cloud/make-secrets.sh
case_ "direct-alb-check without edge outputs" "edge" 60 \
  CF_DOMAIN= ALB_DNS= scripts/cloud/direct-alb-check.sh
case_ "rotate-origin-secret without a distribution" "distribution" 60 \
  PATH="$STUB:$PATH" DIST_ID= scripts/cloud/rotate-origin-secret.sh

say "3. a POOLER database URL must be refused (the documented Neon trap)"
# PgBouncer transaction mode breaks sqlx prepared statements and LISTEN/NOTIFY.
# Catching it here is the difference between a clear refusal and a deployment
# that comes up and then misbehaves in ways that look like product bugs.
case_ "make-secrets rejects a -pooler endpoint" "pooler" 30 \
  PATH="$STUB:$PATH" \
  FLUIDBOX_CLOUD_DATABASE_URL="postgres://u:p@ep-x-pooler.aws.neon.tech/db" \
  FLUIDBOX_CLOUD_LITELLM_DATABASE_URL="postgres://u:p@ep-y.aws.neon.tech/db" \
  FLUIDBOX_CLOUD_ANTHROPIC_API_KEY=sk-test \
  scripts/cloud/make-secrets.sh

say "4. local proof harnesses must refuse the DEV database"
case_ "kind validation refuses the dev database"  "DEV database" 30 DRILL_DB=fluidbox scripts/cloud/m1-containment-drill.sh
case_ "onboarding rehearsal refuses the dev database" "DEV database" 30 REHEARSAL_DB=fluidbox scripts/cloud/m1-onboarding-rehearsal.sh

say "5. a missing binary must be named"
case_ "rehearsal names a missing server binary" "binary" 30 \
  REHEARSAL_DB=fluidbox_smoke PROOF_SERVER_BIN=/nonexistent/fluidbox-server scripts/cloud/m1-onboarding-rehearsal.sh

{
  echo "# Operator-toolkit failure-path smoke test"
  echo
  echo "Run $(date -u +%FT%TZ) by \`scripts/cloud/guardrail-smoke.sh\`. Each case removes"
  echo "one prerequisite and asserts the script stops immediately with an actionable"
  echo "message — never a hang, never a silent success. Nothing is mutated."
  echo
  echo "Result: **$PASS passed, $FAILN failed**."
  echo
  echo "| case | expected in output | verdict | first line |"
  echo "|---|---|---|---|"
  cat "$WORK/rows.md"
  echo
  echo "The root-refusal cases are the load-bearing ones: this toolkit is meant to"
  echo "be used AFTER the M1.0 ceremony retires the root key, and a script that"
  echo "quietly worked under root credentials would undermine the whole guardrail."
} > "$OUT"

say "verdict"
echo "  PASS=$PASS FAIL=$FAILN   report: $OUT"
[ "$FAILN" -eq 0 ] && ok "every guard refuses cleanly and says why" || fail "some guards are missing or unclear"
exit $((FAILN > 0))
