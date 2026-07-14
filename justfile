set dotenv-load := true

# List available recipes
default:
    @just --list

# ── Dev ──────────────────────────────────────────────────────────────────

# One-command bootstrap for a fresh clone (idempotent): tools check, .env +
# generated secrets, dashboard env, pnpm install, runner image, then doctor.
setup:
    bash scripts/setup.sh

# Validate the local environment; every ✗/⚠ prints its exact fix.
doctor:
    bash scripts/doctor.sh

# Everything: LiteLLM gateway + server + web (ctrl-c stops all)
dev:
    just gateway-up
    (trap 'kill 0' EXIT; cargo run -p fluidbox-server & (cd apps/web && pnpm dev) & wait)

# Run the Rust control plane (migrations run automatically on boot)
server:
    cargo run -p fluidbox-server

# Run the dashboard
web:
    cd apps/web && pnpm dev

# Start / stop the LiteLLM model gateway
gateway-up:
    docker compose -f deploy/docker-compose.dev.yml up -d litellm

gateway-down:
    docker compose -f deploy/docker-compose.dev.yml down

# Build the Claude sandbox runner image (context = images/, shared with codex)
sandbox-build:
    docker build -t $FLUIDBOX_SANDBOX_IMAGE -f images/sandbox-runner/Dockerfile images

# Build the Codex runner image (the second harness)
codex-build:
    docker build -t ${FLUIDBOX_CODEX_SANDBOX_IMAGE:-fluidbox-codex-runner:dev} -f images/codex-runner/Dockerfile images

# ── Database ─────────────────────────────────────────────────────────────

# Provision a Neon project and write the DIRECT connection string into .env
neon-setup:
    ./scripts/neon-setup.sh

# psql into DATABASE_URL
db:
    psql "$DATABASE_URL"

# Remove e2e/test cruft from the DB (sessions, test agents, subscriptions,
# schedules, bundles). Preserves the tenant, policies, connections, and the
# seed agents. DRY-RUN by default; pass `apply` to commit. See scripts/db-clean.sh.
db-clean *ARGS:
    bash scripts/db-clean.sh {{ARGS}}

# ── Quality ──────────────────────────────────────────────────────────────

fmt:
    cargo fmt --all

lint:
    cargo clippy --workspace --all-targets -- -D warnings

test:
    cargo test --workspace

check: fmt lint test
    cd apps/web && pnpm build

# ── E2E acceptance ───────────────────────────────────────────────────────

# Full acceptance suite: live demo A + governance + git workspaces + api triggers + failure paths.
# Owns the stack (requires :8787 free — stop `just dev` first). The live
# phase self-skips without ANTHROPIC_API_KEY; E2E_SKIP_LIVE=1 skips it too.
e2e:
    bash scripts/e2e.sh

# Push policies/*.yaml to the running control plane (bumps policy version;
# in-flight runs keep their frozen snapshot).
policy-sync:
    bash scripts/policy-sync.sh

# ── Connector catalog import (offline dev tool) ──────────────────────────
#
# Regenerate the append-only connector-catalog import migration from a PINNED
# open-connector checkout (Apache-2.0; see NOTICE). Clone + pin + generate its
# catalog JSON first, then point SRC at it and pass the exact commit:
#
#   git -C ../open-connector rev-parse HEAD          # the pin
#   (cd ../open-connector && npm ci && npm run generate:catalog)
#   just catalog-import ../open-connector <commit> migrations/0010_catalog_import.sql
#
# Deterministic: same commit → identical SQL. Every row is untrusted,
# community-tier, provenance-tagged; REST-only providers import reference-only.
catalog-import SRC SHA OUT="migrations/0010_catalog_import.sql":
    cargo run -p fluidbox-catalog-import -- --src {{SRC}} --sha {{SHA}} --out {{OUT}}
