#!/usr/bin/env bash
# Render-time assertions for the shipped compose files.
#
# Why this exists: `deploy/helm/chart-assertions.sh` guards the Helm chart, and
# nothing guarded the compose files at all — no CI job, script, or `just` recipe
# even referenced `docker-compose.eval.yml`. The eval profile spent three
# releases publishing an admin token that is committed to this repository, on a
# port reachable from the whole network segment, next to a mounted docker socket.
# That is not a bug you fix once; it is a property you assert.
#
# Costs seconds, needs no daemon and no network: everything here is a property of
# the FILES.
#
#   deploy/compose-assertions.sh
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

pass=0
fail=0
ok()   { printf '  ok        %s\n' "$1"; pass=$((pass + 1)); }
bad()  { printf '  FAIL      %s\n' "$1"; shift; for l in "$@"; do printf '            %s\n' "$l"; done; fail=$((fail + 1)); }

EVAL=deploy/docker-compose.eval.yml
DEV=deploy/docker-compose.dev.yml
DEMO=deploy/docker-compose.demo.yml

for f in "$EVAL" "$DEV" "$DEMO"; do
  [ -f "$f" ] || { bad "missing compose file" "$f"; }
done

# ── 1. No compose file may carry a hardcoded admin-token default ────────────
#
# `${FLUIDBOX_ADMIN_TOKEN:-<literal>}` is the exact shape that shipped
# `fluidbox-eval-only`. A required-variable form (`:?`) or a bare `${VAR}` is
# fine; a `:-` default is not, because the default is public by construction.
for f in "$EVAL" "$DEV" "$DEMO"; do
  [ -f "$f" ] || continue
  if grep -nE 'FLUIDBOX_ADMIN_TOKEN:-' "$f" >/dev/null 2>&1; then
    bad "$f publishes an admin-token default" \
        "$(grep -nE 'FLUIDBOX_ADMIN_TOKEN:-' "$f")" \
        "fix: make it required — \${FLUIDBOX_ADMIN_TOKEN:?<how to generate one>}"
  else
    ok "$f has no hardcoded admin-token default"
  fi
done

# The eval profile must go further and REQUIRE the token, so `up` refuses rather
# than booting an unauthenticated-in-practice control plane.
if grep -qE 'FLUIDBOX_ADMIN_TOKEN:\?' "$EVAL"; then
  ok "$EVAL requires FLUIDBOX_ADMIN_TOKEN (compose refuses to start without it)"
else
  bad "$EVAL does not REQUIRE an admin token" \
      "fix: FLUIDBOX_ADMIN_TOKEN: \${FLUIDBOX_ADMIN_TOKEN:?...}"
fi

# ── 2. Published ports: loopback unless deliberately justified ──────────────
#
# Extracted from the file rather than from `docker compose config`, so this runs
# with no daemon. Docker's short syntax with no host-IP part binds 0.0.0.0.
#
# The eval API port (8787) is the ONE allowed exception and it is allowed only
# while it stays explained: sandboxes are sibling containers on per-run networks
# and reach the control plane over host.docker.internal, so a loopback publish
# breaks every run. The assertion therefore is not "8787 is loopback" (that
# would be false and would break the product) but "8787 is bind-configurable and
# the file says why", plus "everything else is loopback".
published_ports() { # file -> lines like `- "127.0.0.1:5433:5432"`
  # POSIX classes, not \s: BSD sed (macOS) does not understand \s, and this
  # script has to give the same answer on a maintainer's laptop and in CI.
  grep -nE '^[[:space:]]*-[[:space:]]*"[^"]*:[0-9]+"' "$1" 2>/dev/null || true
}

check_loopback() { # file, allow-regex-for-exceptions
  local f="$1" exc="$2" line spec bad_any=0
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    spec=$(sed -E 's/^[0-9]+:[[:space:]]*-[[:space:]]*"([^"]*)".*/\1/' <<<"$line")
    # An exception is allowed through by pattern.
    if [ -n "$exc" ] && printf '%s' "$spec" | grep -qE "$exc"; then
      continue
    fi
    if ! printf '%s' "$spec" | grep -qE '^127\.0\.0\.1:'; then
      bad "$f publishes a non-loopback port: $spec" \
          "at $f:${line%%:*}" \
          "fix: prefix it with 127.0.0.1: , or add a justified exception here"
      bad_any=1
    fi
  done <<<"$(published_ports "$f")"
  [ "$bad_any" -eq 0 ] && ok "$f publishes only loopback ports (plus documented exceptions)"
}

# eval: the API port is the documented exception; it must be bind-configurable.
if grep -qE '\$\{FLUIDBOX_EVAL_API_BIND:-0\.0\.0\.0\}:8787:8787' "$EVAL"; then
  ok "$EVAL API port is bind-configurable via FLUIDBOX_EVAL_API_BIND"
else
  bad "$EVAL API port is not bind-configurable" \
      "fix: - \"\${FLUIDBOX_EVAL_API_BIND:-0.0.0.0}:8787:8787\""
fi
# ...and the exception must stay explained in the file, so a future reader does
# not "clean it up" into a silent 0.0.0.0 publish.
if grep -q 'host.docker.internal' "$EVAL"; then
  ok "$EVAL explains why its API port cannot be loopback"
else
  bad "$EVAL no longer explains the non-loopback API port" \
      "fix: keep the host.docker.internal rationale in the file"
fi
check_loopback "$EVAL" 'FLUIDBOX_EVAL_API_BIND'
check_loopback "$DEV" ''
check_loopback "$DEMO" ''

# ── 3. The dashboard must never be published off-box ────────────────────────
if grep -qE '^\s*-\s*"127\.0\.0\.1:3000:3000"' "$EVAL"; then
  ok "$EVAL dashboard is loopback-only"
else
  bad "$EVAL dashboard is not loopback-only" \
      "It carries the admin token server-side in admin web mode." \
      "fix: - \"127.0.0.1:3000:3000\""
fi

printf '\n%s: %d passed, %d failed\n' "$(basename "$0")" "$pass" "$fail"
[ "$fail" -eq 0 ] || exit 1
