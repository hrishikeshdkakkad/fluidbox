#!/usr/bin/env bash
# Preflight: validate the local environment against the documented gotchas
# (.env.example, CONTRIBUTING.md) and print the exact fix for anything wrong.
#
# Usage: just doctor   (or: bash scripts/doctor.sh)
# Prints ✅/⚠️/❌ per check; never echoes secret values, only variable names.
# Exits non-zero only on hard failures (❌).
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

fails=0; warns=0
ok()   { printf "  \033[1;32m✓\033[0m %s\n" "$1"; }
warn() { printf "  \033[1;33m⚠\033[0m %s\n      ↳ %s\n" "$1" "$2"; warns=$((warns+1)); }
bad()  { printf "  \033[1;31m✗\033[0m %s\n      ↳ %s\n" "$1" "$2"; fails=$((fails+1)); }
say()  { printf "\n\033[1;36m== %s ==\033[0m\n" "$1"; }

# Read KEY from an env file without sourcing it (values never get echoed).
env_get() { grep -m1 "^$2=" "$1" 2>/dev/null | cut -d= -f2-; }

say "tools"
for tool in cargo docker just pnpm node; do
  if command -v "$tool" >/dev/null 2>&1; then
    ok "$tool ($(command -v "$tool"))"
  else
    case "$tool" in
      cargo) fix="install Rust via https://rustup.rs (rust-toolchain.toml pins the version)";;
      docker) fix="install Docker: https://docs.docker.com/get-docker/";;
      just) fix="install just: https://github.com/casey/just (brew install just)";;
      pnpm) fix="install pnpm: https://pnpm.io/installation (corepack enable pnpm)";;
      node) fix="install Node 24+: https://nodejs.org";;
    esac
    bad "$tool not found" "$fix"
  fi
done

docker_up=0
if command -v docker >/dev/null 2>&1; then
  if docker info >/dev/null 2>&1; then
    ok "docker daemon running"; docker_up=1
    docker compose version >/dev/null 2>&1 \
      && ok "docker compose v2" \
      || bad "docker compose v2 missing" "the LiteLLM gateway needs Compose v2 (ships with Docker Desktop)"
  else
    bad "docker daemon not running" "start Docker Desktop (or the docker service)"
  fi
fi

if command -v node >/dev/null 2>&1; then
  node_major=$(node -e 'process.stdout.write(String(process.versions.node.split(".")[0]))')
  if [ "$node_major" -ge 22 ]; then
    ok "node v$(node -v | tr -d v) (>= 22)"
  else
    warn "node v$(node -v | tr -d v) is old" "the dashboard is developed against Node 24 — upgrade if the web build misbehaves"
  fi
fi

say ".env"
ENV="$ROOT/.env"
if [ ! -f "$ENV" ]; then
  bad ".env missing" "run: just setup   (copies .env.example and generates secrets)"
else
  ok ".env exists"

  db_url=$(env_get "$ENV" DATABASE_URL)
  case "$db_url" in
    ""|*ep-xxx*) bad "DATABASE_URL not set" "run: just neon-setup   (provisions Neon and writes the DIRECT string into .env)";;
    *-pooler*)   bad "DATABASE_URL is the POOLED (-pooler) Neon string" "use the DIRECT endpoint — PgBouncer transaction mode breaks sqlx prepared statements and LISTEN/NOTIFY (just neon-setup fetches it)";;
    *)
      ok "DATABASE_URL set (direct endpoint)"
      if command -v psql >/dev/null 2>&1; then
        if psql "$db_url" -Atc 'select 1' >/dev/null 2>&1; then
          ok "database reachable"
        else
          warn "database not reachable right now" "Neon scale-to-zero can add a cold-start delay; retry, or check the connection string with: just db"
        fi
      fi
      ;;
  esac

  bind=$(env_get "$ENV" FLUIDBOX_BIND)
  case "$bind" in
    0.0.0.0:*|"") ok "FLUIDBOX_BIND=${bind:-<default>} (reachable from sandboxes)";;
    *) bad "FLUIDBOX_BIND=$bind is a loopback bind" "set FLUIDBOX_BIND=0.0.0.0:8787 — sandboxes reach the control plane via host.docker.internal, which cannot reach 127.0.0.1";;
  esac

  admin=$(env_get "$ENV" FLUIDBOX_ADMIN_TOKEN)
  case "$admin" in
    ""|change-me) bad "FLUIDBOX_ADMIN_TOKEN is the placeholder" "run: just setup   (generates it), or: openssl rand -hex 32";;
    *) ok "FLUIDBOX_ADMIN_TOKEN set";;
  esac

  cred=$(env_get "$ENV" FLUIDBOX_CREDENTIAL_KEY)
  if [ -z "$cred" ]; then
    warn "FLUIDBOX_CREDENTIAL_KEY empty — Connections and event ingress are disabled" "run: just setup   (generates it), or: openssl rand -hex 32"
  elif python3 -c '
import sys, base64, binascii
v = sys.argv[1]
def is32(b): return len(b) == 32
try:
    if is32(binascii.unhexlify(v)): sys.exit(0)
except Exception: pass
try:
    if is32(base64.b64decode(v, validate=True)): sys.exit(0)
except Exception: pass
sys.exit(1)' "$cred" 2>/dev/null; then
    ok "FLUIDBOX_CREDENTIAL_KEY decodes to 32 bytes"
  else
    bad "FLUIDBOX_CREDENTIAL_KEY does not decode to 32 bytes" "generate a valid key: openssl rand -hex 32 (rotating it orphans sealed credentials — reconnect afterwards)"
  fi

  anthropic=$(env_get "$ENV" ANTHROPIC_API_KEY)
  case "$anthropic" in
    ""|sk-ant-api03-...) warn "ANTHROPIC_API_KEY not set" "live agent runs and the live e2e phase self-skip without it; add it to .env (only the LiteLLM container ever reads it)";;
    *) ok "ANTHROPIC_API_KEY set";;
  esac

  openai=$(env_get "$ENV" OPENAI_API_KEY)
  [ -z "$openai" ] \
    && warn "OPENAI_API_KEY not set (optional)" "only needed for the Codex harness; its live e2e tier self-skips without it" \
    || ok "OPENAI_API_KEY set"

  litellm=$(env_get "$ENV" LITELLM_MASTER_KEY)
  case "$litellm" in
    ""|sk-litellm-change-me) warn "LITELLM_MASTER_KEY is the placeholder" "works locally (server and gateway share .env) but generate a real one: just setup";;
    *) ok "LITELLM_MASTER_KEY set";;
  esac

  if [ "$docker_up" = 1 ]; then
    say "docker images"
    sandbox_image=$(env_get "$ENV" FLUIDBOX_SANDBOX_IMAGE); sandbox_image=${sandbox_image:-fluidbox-sandbox-runner:dev}
    docker image inspect "$sandbox_image" >/dev/null 2>&1 \
      && ok "sandbox runner image $sandbox_image built" \
      || bad "sandbox runner image $sandbox_image not built" "run: just sandbox-build"
    codex_image=$(env_get "$ENV" FLUIDBOX_CODEX_SANDBOX_IMAGE); codex_image=${codex_image:-fluidbox-codex-runner:dev}
    docker image inspect "$codex_image" >/dev/null 2>&1 \
      && ok "codex runner image $codex_image built" \
      || warn "codex runner image $codex_image not built (optional)" "only needed for the Codex harness: just codex-build"
    docker compose -f "$ROOT/deploy/docker-compose.dev.yml" ps --status running 2>/dev/null | grep -q litellm \
      && ok "LiteLLM gateway running" \
      || warn "LiteLLM gateway not running" "just dev starts it automatically, or run: just gateway-up"
  fi
fi

say "dashboard (apps/web)"
WEB_ENV="$ROOT/apps/web/.env.local"
if [ ! -f "$WEB_ENV" ]; then
  bad "apps/web/.env.local missing — the dashboard proxy has no admin token (every request 401s)" "run: just setup   (writes it from .env)"
else
  ok "apps/web/.env.local exists"
  if [ -f "$ENV" ]; then
    web_token=$(env_get "$WEB_ENV" FLUIDBOX_ADMIN_TOKEN)
    root_token=$(env_get "$ENV" FLUIDBOX_ADMIN_TOKEN)
    if [ -n "$root_token" ] && [ "$web_token" = "$root_token" ]; then
      ok "FLUIDBOX_ADMIN_TOKEN matches .env"
    else
      bad "FLUIDBOX_ADMIN_TOKEN in apps/web/.env.local does not match .env" "run: just setup   (re-syncs it) — a mismatch makes the dashboard 401 silently"
    fi
  fi
fi
[ -d "$ROOT/apps/web/node_modules" ] \
  && ok "web dependencies installed" \
  || warn "apps/web/node_modules missing" "run: cd apps/web && pnpm install   (just setup does this too)"

say "control plane"
if curl -fsS -m 2 "http://127.0.0.1:8787/v1/health" >/dev/null 2>&1; then
  ok "server responding on :8787 (note: just e2e needs this port free — stop just dev first)"
else
  ok "port 8787 free (start everything with: just dev)"
fi

echo
if [ "$fails" -gt 0 ]; then
  printf "\033[1;31m%d problem(s)\033[0m, %d warning(s) — fix the ✗ items above.\n" "$fails" "$warns"
  exit 1
elif [ "$warns" -gt 0 ]; then
  printf "\033[1;32mready\033[0m with %d warning(s) — nothing blocking. Run: just dev\n" "$warns"
else
  printf "\033[1;32mall green.\033[0m Run: just dev\n"
fi
