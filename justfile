set dotenv-load := true

# List available recipes
default:
    @just --list

# ── Dev ──────────────────────────────────────────────────────────────────

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

# Build the sandbox runner image
sandbox-build:
    docker build -t $FLUIDBOX_SANDBOX_IMAGE images/sandbox-runner

# ── Database ─────────────────────────────────────────────────────────────

# Provision a Neon project and print the DIRECT connection string
neon-setup:
    ./scripts/neon-setup.sh

# psql into DATABASE_URL
db:
    psql "$DATABASE_URL"

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
