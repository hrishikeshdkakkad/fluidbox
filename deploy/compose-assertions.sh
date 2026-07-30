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

# EVERY assignment must be a required-variable substitution — checked one
# occurrence at a time, not once per file.
#
# This check used to be `grep -q 'FLUIDBOX_ADMIN_TOKEN:?' "$EVAL"` — "does the
# required form appear ANYWHERE in this file". Two services set the token
# (`server` and `web`), so that passed while the server's value was a hardcoded
# literal, which is BLK-04 itself: a working admin credential published in this
# repository. Verified: reintroducing `FLUIDBOX_ADMIN_TOKEN: "fluidbox-eval-only"`
# on the server left the suite fully green.
#
# The `:-` check above tests one SPELLING of the defect. This tests the property:
# whatever the spelling, the value must come from the environment and must have
# no fallback.
for f in "$EVAL" "$DEV" "$DEMO"; do
  [ -f "$f" ] || continue
  # Whole-line comments are stripped first: the eval header explains the OLD
  # default in prose, and a checker that cannot tell an assignment from a
  # description of the bug it hunts fails on the file that fixed the bug.
  assignments=$(grep -vE '^[[:space:]]*#' "$f" | grep -E '^[[:space:]]*FLUIDBOX_ADMIN_TOKEN:' || true)
  offenders=""
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    printf '%s' "$line" | grep -qE '\$\{FLUIDBOX_ADMIN_TOKEN:\?' \
      || offenders="$offenders
      $line"
  done <<<"$assignments"
  if [ -n "$offenders" ]; then
    bad "$f has an admin-token assignment that is not a required substitution" \
        "$offenders" \
        "fix: FLUIDBOX_ADMIN_TOKEN: \"\${FLUIDBOX_ADMIN_TOKEN:?<how to generate one>}\"" \
        "A literal here is a working credential committed to this repository."
  else
    ok "$f: every admin-token assignment is a required substitution"
  fi
done

# ...and the eval profile must actually SET it, so `up` refuses rather than
# booting a control plane whose admin surface is unauthenticated in practice.
if grep -vE '^[[:space:]]*#' "$EVAL" | grep -qE '^[[:space:]]*FLUIDBOX_ADMIN_TOKEN:'; then
  ok "$EVAL requires FLUIDBOX_ADMIN_TOKEN (compose refuses to start without it)"
else
  bad "$EVAL does not set an admin token at all" \
      "fix: FLUIDBOX_ADMIN_TOKEN: \${FLUIDBOX_ADMIN_TOKEN:?...}"
fi

# ── 2. Published ports: loopback unless deliberately justified ──────────────
#
# Extracted from the file rather than from `docker compose config`, so this runs
# with no daemon. Docker's short syntax with no host-IP part binds 0.0.0.0.
#
# The eval API port (8787) is the ONE allowed exception, and it is allowed only
# while it stays CONFIGURABLE and EXPLAINED. Sandboxes are sibling containers on
# per-run networks that reach the control plane over host.docker.internal;
# whether a loopback publish stays reachable from them depends on how the engine
# forwards ports (measured working on colima, expected to break on native Linux
# Docker), so the default is open for portability rather than by necessity.
#
# The assertion therefore is not "8787 is loopback" — that would break the
# product on some engines — but "8787 is bind-configurable and the file explains
# the trade-off", plus "everything else is loopback".
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
  ok "$EVAL explains the trade-off behind its non-loopback API default"
else
  bad "$EVAL no longer explains the non-loopback API default" \
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

# ── 4. Every file must still PARSE ─────────────────────────────────────────
#
# Learned the hard way while writing the assertions above: a required-variable
# message containing ": " turned the whole eval file into invalid YAML, and every
# grep-based assertion here passed anyway because a grep does not care whether
# the document is well-formed. Only `docker compose config` caught it. So the
# guard now includes the one check that is not about content at all.
#
# Needs a docker CLI (not a running daemon — `config` is local parsing). Skipped
# with a visible note rather than silently when docker is absent, so a green run
# in an environment without it never reads as "the files parse".
if command -v docker >/dev/null 2>&1; then
  for f in "$EVAL" "$DEV" "$DEMO"; do
    [ -f "$f" ] || continue
    # Every required variable gets a dummy value: we are checking the SHAPE of
    # the document, not whether the caller configured a deployment.
    if err=$(FLUIDBOX_ADMIN_TOKEN=parse-check ANTHROPIC_API_KEY=parse-check \
             LITELLM_MASTER_KEY=parse-check POSTGRES_PASSWORD=parse-check \
             docker compose -f "$f" config 2>&1 >/dev/null); then
      ok "$f parses (docker compose config)"
    else
      bad "$f does not parse" "$(printf '%s' "$err" | head -3)"
    fi
  done
  # ...and the required-variable refusal actually refuses.
  if FLUIDBOX_ADMIN_TOKEN= docker compose -f "$EVAL" config >/dev/null 2>&1; then
    bad "$EVAL accepted an EMPTY admin token" \
        "the :? form must refuse an empty value, not just an unset one"
  else
    ok "$EVAL refuses an empty admin token"
  fi

  # The same property again, but measured on the RENDERED document rather than
  # on the source text. The grep above can only reject spellings it anticipates;
  # this asks the question that actually matters — "after compose resolves every
  # substitution, does any service hold a token the operator did not supply?" —
  # and a literal cannot survive it whatever its spelling, because a literal does
  # not change when the environment does.
  sentinel="fbx-rendered-token-sentinel-$$"
  rendered=$(FLUIDBOX_ADMIN_TOKEN="$sentinel" ANTHROPIC_API_KEY=parse-check \
             LITELLM_MASTER_KEY=parse-check POSTGRES_PASSWORD=parse-check \
             docker compose -f "$EVAL" config 2>/dev/null \
             | grep -E '^[[:space:]]*FLUIDBOX_ADMIN_TOKEN:' || true)
  strays=$(printf '%s\n' "$rendered" | grep -v "$sentinel" | grep -E '[^[:space:]]' || true)
  if [ -z "$rendered" ]; then
    bad "$EVAL renders no FLUIDBOX_ADMIN_TOKEN at all" \
        "the admin surface would be unauthenticated in practice"
  elif [ -n "$strays" ]; then
    bad "$EVAL renders an admin token the operator did not supply" \
        "$strays" \
        "every rendered value must be the caller's, not a literal baked into the file"
  else
    ok "$EVAL renders the operator's admin token in every service that sets it"
  fi
else
  printf '  SKIP      %s\n' "docker absent — compose parse check not run"
fi

printf '\n%s: %d passed, %d failed\n' "$(basename "$0")" "$pass" "$fail"
[ "$fail" -eq 0 ] || exit 1
