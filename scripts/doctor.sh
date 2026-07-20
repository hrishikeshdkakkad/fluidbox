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

  # KMS / envelope sealing (Phase D). All hints here are non-fatal — KMS is an
  # opt-in hardening. Variable NAMES only, never values.
  say "KMS / envelope sealing"
  kms_mode=$(env_get "$ENV" FLUIDBOX_KMS_MODE); kms_mode=${kms_mode:-off}
  case "$kms_mode" in
    off|"")
      ok "FLUIDBOX_KMS_MODE=off (legacy single-key sealing; FLUIDBOX_CREDENTIAL_KEY seals at rest)";;
    static)
      ok "FLUIDBOX_KMS_MODE=static (per-tenant DEKs wrapped by a static KEK)"
      [ -n "$(env_get "$ENV" FLUIDBOX_KMS_STATIC_KEK)" ] \
        && ok "FLUIDBOX_KMS_STATIC_KEK set" \
        || warn "FLUIDBOX_KMS_STATIC_KEK empty — the server will refuse to boot" "static mode needs a 32-byte KEK: openssl rand -hex 32";;
    aws)
      ok "FLUIDBOX_KMS_MODE=aws (per-tenant DEKs wrapped by AWS KMS)"
      [ -n "$(env_get "$ENV" FLUIDBOX_KMS_AWS_KEY_ID)" ] \
        && ok "FLUIDBOX_KMS_AWS_KEY_ID set" \
        || warn "FLUIDBOX_KMS_AWS_KEY_ID empty — the server will refuse to boot" "aws mode needs the KMS key id/ARN (see docs/hosted/kms-operations.md §3 for the IAM grant)";;
    *)
      warn "FLUIDBOX_KMS_MODE=$kms_mode unrecognized" "expected: off | static | aws";;
  esac
  # Legacy (v1) parity — needs psql, a reachable DB, and migration 0014 applied.
  if command -v psql >/dev/null 2>&1 && [ -n "${db_url:-}" ]; then
    legacy_sql="select family||' '||legacy from (
      select 'integration_connections.credential_sealed' as family, count(*) filter (where credential_sealed is not null and credential_key_version=1) as legacy from integration_connections
      union all select 'integration_connections.webhook_secret_sealed', count(*) filter (where webhook_secret_sealed is not null and webhook_secret_key_version=1) from integration_connections
      union all select 'integration_connections.client_secret_sealed', count(*) filter (where client_secret_sealed is not null and client_secret_key_version=1) from integration_connections
      union all select 'trigger_subscriptions.callback_secret_sealed', count(*) filter (where callback_secret_sealed is not null and callback_secret_key_version=1) from trigger_subscriptions
      union all select 'github_app_registrations.pem_sealed', count(*) filter (where pem_sealed is not null and pem_key_version=1) from github_app_registrations
      union all select 'github_app_registrations.webhook_secret_sealed', count(*) filter (where webhook_secret_sealed is not null and webhook_secret_key_version=1) from github_app_registrations
      union all select 'github_app_registrations.client_secret_sealed', count(*) filter (where client_secret_sealed is not null and client_secret_key_version=1) from github_app_registrations
      union all select 'org_idp_configs.client_secret_sealed', count(*) filter (where client_secret_sealed is not null and client_secret_key_version=1) from org_idp_configs
      union all select 'login_flows.pkce_verifier_sealed', count(*) filter (where pkce_verifier_sealed is not null and pkce_verifier_key_version=1) from login_flows
    ) s where legacy > 0"
    legacy_rows=$(psql "$db_url" -Atc "$legacy_sql" 2>/dev/null)
    if [ -z "$legacy_rows" ]; then
      : # all zero, DB unreachable, or 0014 not applied — stay quiet (non-fatal)
    else
      total=$(printf '%s\n' "$legacy_rows" | awk '{s+=$2} END{print s}')
      if [ "$kms_mode" != off ]; then
        warn "$total legacy (v1) sealed row(s) remain under KMS mode" "run the re-seal to retire FLUIDBOX_CREDENTIAL_KEY: POST /v1/admin/reseal, then GET /v1/admin/reseal until legacy_total=0 (docs/hosted/kms-operations.md §5). Per-family:"
        printf '%s\n' "$legacy_rows" | while read -r fam n; do printf "        %s: %s\n" "$fam" "$n"; done
      else
        ok "$total legacy (v1) sealed row(s) — expected with KMS off"
      fi
    fi
  fi

  # LLM upstream auth (Phase D). Non-fatal hints; variable NAMES only, never values.
  say "LLM upstream auth"
  llm_mode=$(env_get "$ENV" FLUIDBOX_LLM_KEY_MODE); llm_mode=${llm_mode:-shared}
  upstream_url=$(env_get "$ENV" LLM_UPSTREAM_URL)
  case "$llm_mode" in
    shared|"")
      ok "FLUIDBOX_LLM_KEY_MODE=shared (facade presents one upstream key on every model request)"
      # D7: shared mode refuses to boot on an EMPTY resolved upstream key.
      case "$upstream_url" in
        *api.anthropic.com*)
          [ -n "$(env_get "$ENV" ANTHROPIC_API_KEY)" ] \
            || warn "shared mode + direct-Anthropic upstream but ANTHROPIC_API_KEY empty — the server refuses to boot" "set ANTHROPIC_API_KEY (the facade presents it on every request)";;
        *)
          [ -n "$(env_get "$ENV" LITELLM_MASTER_KEY)" ] \
            || warn "shared mode but LITELLM_MASTER_KEY empty — the server refuses to boot" "set LITELLM_MASTER_KEY (the facade presents it on every request)";;
      esac
      [ "$(env_get "$ENV" FLUIDBOX_REQUIRE_SSO)" = 1 ] \
        && warn "FLUIDBOX_REQUIRE_SSO=1 with shared LLM mode — the facade returns 503 (tenant_llm_keys_required) for EVERY model request" "set FLUIDBOX_LLM_KEY_MODE=tenant for hosted deployments";;
    tenant)
      ok "FLUIDBOX_LLM_KEY_MODE=tenant (per-tenant LiteLLM virtual keys; master key confined to provisioning)"
      case "$upstream_url" in
        *api.anthropic.com*)
          warn "tenant mode requires a LiteLLM upstream, not direct Anthropic — the server refuses to boot" "virtual keys are a LiteLLM feature; point LLM_UPSTREAM_URL at LiteLLM";;
      esac
      [ -n "$(env_get "$ENV" LITELLM_MASTER_KEY)" ] \
        && ok "LITELLM_MASTER_KEY set (virtual-key provisioning credential)" \
        || warn "tenant mode but LITELLM_MASTER_KEY empty — the server refuses to boot" "set LITELLM_MASTER_KEY (mints virtual keys via /key/generate)"
      admin_url=$(env_get "$ENV" FLUIDBOX_LLM_ADMIN_URL)
      [ -n "$admin_url" ] \
        && ok "FLUIDBOX_LLM_ADMIN_URL set (virtual-key admin plane)" \
        || ok "FLUIDBOX_LLM_ADMIN_URL unset — defaults to LLM_UPSTREAM_URL"
      warn "tenant mode needs LiteLLM backed by its OWN Postgres for /key/* — not wired in the default dev compose" "prerequisite; see docs/hosted/kms-operations.md §8 (per-tenant LiteLLM virtual keys)";;
    *)
      warn "FLUIDBOX_LLM_KEY_MODE=$llm_mode unrecognized" "expected: shared | tenant";;
  esac
  # A REAL-browser OAuth Connect needs an https public URL: the __Host- flow cookie
  # is dropped by browsers on http. curl-based e2e is unaffected (Task 4 review).
  pub_url=$(env_get "$ENV" FLUIDBOX_PUBLIC_URL); pub_url=${pub_url:-http://127.0.0.1:8787}
  case "$pub_url" in
    https://*) : ;;
    *) warn "FLUIDBOX_PUBLIC_URL is http — a REAL-browser OAuth Connect drops the __Host-fbx_oauth_flow cookie" "local curl-based flows work; a hosted deployment needs an https FLUIDBOX_PUBLIC_URL";;
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
