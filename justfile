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

# Local Kubernetes dev: kind + Calico + image load + helm-install guidance.
k8s-dev:
    bash scripts/k8s-dev.sh

# K8s preflight (kube context, StorageClass, enforcing CNI, credential Secret).
k8s-doctor NS="fluidbox":
    bash scripts/k8s-doctor.sh {{NS}}

# Build the in-pod workspace collector image.
collector-build:
    docker build -t ${FLUIDBOX_COLLECTOR_IMAGE:-fluidbox-workspaced:dev} -f deploy/workspaced.Dockerfile .

# Everything: Postgres + LiteLLM gateway + server + web (ctrl-c stops the
# host processes; the containers keep running — `just db-down` stops the DB).
dev:
    just db-up
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

# Stops ONLY the gateway. It used to `down` the whole composition, which now
# would take the database with it.
gateway-down:
    docker compose -f deploy/docker-compose.dev.yml stop litellm

# Build the Claude sandbox runner image (context = images/, shared with codex)
sandbox-build:
    docker build -t $FLUIDBOX_SANDBOX_IMAGE -f images/sandbox-runner/Dockerfile images

# Build the Codex runner image (the second harness)
codex-build:
    docker build -t ${FLUIDBOX_CODEX_SANDBOX_IMAGE:-fluidbox-codex-runner:dev} -f images/codex-runner/Dockerfile images

# ── Database ─────────────────────────────────────────────────────────────
#
# Local development runs Postgres in a container with a named volume
# (`fluidbox-pgdata`), published on 127.0.0.1:5433 — 5432 is commonly already
# taken by a Homebrew postgres. Data survives restarts and reboots; only
# `just db-reset` destroys it. The server applies all migrations on boot, so
# a fresh volume needs no manual step.

# Start the local Postgres container and wait until it accepts connections.
db-up:
    docker compose -f deploy/docker-compose.dev.yml up -d --wait postgres

# Stop the database, KEEPING the data volume.
db-down:
    docker compose -f deploy/docker-compose.dev.yml stop postgres

# DESTROY the local database and start a clean one (drops the volume, then
# re-creates it; the next server boot re-runs migrations and re-seeds).
db-reset:
    docker compose -f deploy/docker-compose.dev.yml rm -sf postgres
    docker volume rm -f deploy_fluidbox-pgdata
    just db-up

# Tail the database container's logs.
db-logs:
    docker compose -f deploy/docker-compose.dev.yml logs -f postgres

# Provision a Neon project and write the DIRECT connection string into .env.
# Only needed for a hosted/remote deployment — local dev uses `just db-up`.
neon-setup:
    ./scripts/neon-setup.sh

# psql into DATABASE_URL
db:
    psql "$DATABASE_URL"

# RESET the DB to seed state — drops ALL sessions, ALL capability bundles
# (including real ones like `cloudflare`) and every agent outside the keep-list.
# Preserves the tenant, policies, connections, and registrations. This is a big
# hammer: for removing only test residue, use `db-clean-tests` instead.
# DRY-RUN by default; pass `apply` to commit. See scripts/db-clean.sh.
db-clean *ARGS:
    bash scripts/db-clean.sh {{ARGS}}

# Remove ONLY test-suite residue (fixture agents + their sessions, pmt-bundle-*)
# by EXACT name — safe to run against a DB with real work in it. Run this after
# any sanctioned `just check` / `just e2e`, which write fixtures into the real
# tenant. DRY-RUN by default; pass `apply` to commit. See scripts/db-clean-tests.sh.
db-clean-tests *ARGS:
    bash scripts/db-clean-tests.sh {{ARGS}}

# ── Quality ──────────────────────────────────────────────────────────────

fmt:
    cargo fmt --all

lint:
    cargo clippy --workspace --all-targets -- -D warnings

test:
    cargo test --workspace

# Version drift guard: every in-repo version site must agree with
# Cargo.toml's [workspace.package]. Needs no DB and no network.
version-check:
    bash scripts/version-check.sh

# ── Developer documentation (Redocly) ────────────────────────────────────
#
# docs/api/openapi.yaml is the source of truth for the HTTP surface. Change a
# route in the Rust server, change it there too — `docs-lint` is what stops the
# two drifting silently. Needs no DB and no running server.
#
# Pinned (not @latest): a Redocly release must not silently change lint
# results or generated output. Keep in sync with
# apps/web/scripts/sync-developer-docs.mjs.

redocly := "@redocly/cli@2.41.2"

docs-lint:
    cd docs && npx --yes {{redocly}} lint

# Live-reloading docs site on :4000.
docs:
    cd docs && npx --yes {{redocly}} preview

# Single-file API reference into dist/.
docs-build:
    mkdir -p dist
    cd docs && npx --yes {{redocly}} build-docs api/openapi.yaml -o ../dist/api.html

# Regenerate the dashboard's /developer pages from docs/ (guides + the slim
# reference model + the downloadable spec). Output is checked in — run this
# after editing docs/ and commit the diff.
docs-sync:
    cd apps/web && node scripts/sync-developer-docs.mjs

check: fmt lint test version-check
    cd apps/web && pnpm test
    cd apps/web && pnpm build

# ── E2E acceptance ───────────────────────────────────────────────────────

# Full acceptance suite: live demo A + governance + git workspaces + api triggers + failure paths.
# Owns the stack (requires :8787 free — stop `just dev` first). The live
# phase self-skips without ANTHROPIC_API_KEY; E2E_SKIP_LIVE=1 skips it too.
e2e:
    bash scripts/e2e.sh

# ── Connector catalog import (offline dev tool) ──────────────────────────
#
# Regenerate the append-only connector-catalog import migration from the
# official MCP Registry (PRIMARY, connectable breadth) + optionally a pinned
# open-connector checkout (SUPPLEMENT, REST-only reference cards). Both
# Apache-2.0 (see NOTICE). Every row is untrusted, community-tier, and
# provenance-tagged; same pins → identical SQL.
#
# Registry only (live paging), pinned by date/cursor:
#   just catalog-import-registry 2026-07-14 migrations/0010_catalog_import.sql
#
# Full control (Registry snapshot + open-connector), see the binary's --help:
#   git -C ../open-connector rev-parse HEAD          # the oc pin
#   (cd ../open-connector && npm ci && npm run generate:catalog)
#   cargo run -p fluidbox-catalog-import -- \
#     --registry-url https://registry.modelcontextprotocol.io --registry-ref 2026-07-14 \
#     --open-connector ../open-connector --oc-sha <commit> \
#     --out migrations/0010_catalog_import.sql
catalog-import-registry REF OUT="migrations/0010_catalog_import.sql":
    cargo run -p fluidbox-catalog-import -- \
      --registry-url https://registry.modelcontextprotocol.io \
      --registry-ref {{REF}} --out {{OUT}}
