#!/usr/bin/env bash
# One-command bootstrap for a fresh clone. Idempotent — safe to re-run anytime.
#
#   just setup
#
# Does everything that can be automated:
#   1. verifies the required tools exist (fails fast, lists all missing)
#   2. creates .env from .env.example and generates the local secrets
#      (FLUIDBOX_ADMIN_TOKEN, FLUIDBOX_CREDENTIAL_KEY, LITELLM_MASTER_KEY)
#   3. writes apps/web/.env.local so the dashboard proxy shares the admin token
#   4. installs the dashboard dependencies (pnpm)
#   5. builds the sandbox runner image if it isn't built yet
#   6. runs `just doctor` so what's left (DATABASE_URL, ANTHROPIC_API_KEY)
#      is spelled out with exact fixes
#
# Never overwrites a value you set yourself — only fills placeholders.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV="$ROOT/.env"
WEB_ENV="$ROOT/apps/web/.env.local"

say()  { printf "\n\033[1;36m== %s ==\033[0m\n" "$1"; }
note() { printf "  \033[1;32m→\033[0m %s\n" "$1"; }

env_get() { grep -m1 "^$2=" "$1" 2>/dev/null | cut -d= -f2-; }

# Replace KEY=... in FILE (or append if absent) without touching other lines.
env_set() {
  python3 - "$1" "$2" "$3" <<'PY'
import re, sys
path, key, val = sys.argv[1:4]
lines = open(path).read().splitlines(True)
pat = re.compile(rf"^{re.escape(key)}=")
for i, line in enumerate(lines):
    if pat.match(line):
        lines[i] = f"{key}={val}\n"
        break
else:
    lines.append(f"{key}={val}\n")
open(path, "w").writelines(lines)
PY
}

say "checking tools"
missing=0
for tool in cargo docker just pnpm node python3 openssl; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "  ✗ missing: $tool"; missing=1
  fi
done
if [ "$missing" = 1 ]; then
  echo "install the tools above (see the Prerequisites table in CONTRIBUTING.md) and re-run: just setup"
  exit 1
fi
if ! docker info >/dev/null 2>&1; then
  echo "  ✗ docker daemon not running — start Docker Desktop and re-run: just setup"
  exit 1
fi
note "all tools present"

say ".env"
if [ ! -f "$ENV" ]; then
  cp "$ROOT/.env.example" "$ENV"
  note "created .env from .env.example"
else
  note ".env already exists — filling placeholders only"
fi

fill_secret() { # KEY PLACEHOLDER VALUE
  current=$(env_get "$ENV" "$1")
  if [ -z "$current" ] || [ "$current" = "$2" ]; then
    env_set "$ENV" "$1" "$3"
    note "generated $1"
  fi
}
fill_secret FLUIDBOX_ADMIN_TOKEN    "change-me"              "$(openssl rand -hex 32)"
fill_secret FLUIDBOX_CREDENTIAL_KEY ""                       "$(openssl rand -hex 32)"
fill_secret LITELLM_MASTER_KEY      "sk-litellm-change-me"   "sk-litellm-$(openssl rand -hex 24)"

say "dashboard env (apps/web/.env.local)"
admin_token=$(env_get "$ENV" FLUIDBOX_ADMIN_TOKEN)
[ -f "$WEB_ENV" ] || touch "$WEB_ENV"
[ -n "$(env_get "$WEB_ENV" FLUIDBOX_API_URL)" ] || env_set "$WEB_ENV" FLUIDBOX_API_URL "http://127.0.0.1:8787"
if [ "$(env_get "$WEB_ENV" FLUIDBOX_ADMIN_TOKEN)" != "$admin_token" ]; then
  env_set "$WEB_ENV" FLUIDBOX_ADMIN_TOKEN "$admin_token"
  note "synced FLUIDBOX_ADMIN_TOKEN into apps/web/.env.local (the proxy injects it server-side)"
else
  note "already in sync with .env"
fi

say "dashboard dependencies"
(cd "$ROOT/apps/web" && pnpm install)

say "sandbox runner image"
sandbox_image=$(env_get "$ENV" FLUIDBOX_SANDBOX_IMAGE); sandbox_image=${sandbox_image:-fluidbox-sandbox-runner:dev}
if docker image inspect "$sandbox_image" >/dev/null 2>&1; then
  note "$sandbox_image already built (rebuild after editing images/: just sandbox-build)"
else
  docker build -t "$sandbox_image" -f "$ROOT/images/sandbox-runner/Dockerfile" "$ROOT/images"
  note "built $sandbox_image"
fi
note "codex harness image is optional — build it later with: just codex-build"

say "what's left"
bash "$ROOT/scripts/doctor.sh" || true
