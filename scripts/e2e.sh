#!/usr/bin/env bash
# `just e2e` — the one-command acceptance suite:
#   phase 1: live demo A        (real model; self-skips without key/gateway)
#   phase 2: governance plane   (policy, approvals, autonomy — no model)
#   phase 3: git workspaces     (clone/precedence/cleanup; live tier self-skips)
#   phase 4: api triggers       (scoped tokens, idempotency, signed callbacks)
#   phase 5: scheduled borrowing (cron firing, exactly-once, overlap/missed)
#   phase 6: github pr fan-out  (event spine, dedup, fork tier, publishers)
#   phase 7: capability catalog (bundles, photograph rule, broker, narrowing)
#   phase 8: connector catalog & oauth custody (seeded catalog, custom
#            headers, PKCE dance, rotating refresh, fail-closed reconnect)
#   phase 9: failure paths      (budget stop, watchdog, restart — no model)
# Owns the stack: builds binaries, starts the gateway + control plane.
# Refuses to run while `just dev` holds :8787.
set -uo pipefail
source "$(dirname "$0")/e2e-lib.sh"
load_env
require_cmd docker psql python3 curl git cargo
SUITE_FAIL=0

say "PREFLIGHT"
docker info >/dev/null 2>&1 || { echo "docker daemon not running"; exit 1; }
if port_in_use; then
  echo "port 8787 already serving — stop 'just dev' first; the e2e suite owns the stack"
  exit 1
fi
# ALWAYS rebuild (layer cache makes it fast when unchanged): a stale cached
# image would silently test the old runner. Context = images/ (shared with
# codex) with a per-image -f.
echo "building sandbox image $FLUIDBOX_SANDBOX_IMAGE"
docker build -q -t "$FLUIDBOX_SANDBOX_IMAGE" \
  -f "$ROOT/images/sandbox-runner/Dockerfile" "$ROOT/images" >/dev/null || exit 1
echo "building server + cli"
cargo build -q -p fluidbox-server -p fluidbox-cli || exit 1
docker compose -f "$ROOT/deploy/docker-compose.dev.yml" up -d litellm >/dev/null 2>&1 || true
for _ in $(seq 1 40); do
  curl -fsS -m 2 http://127.0.0.1:4000/health/liveliness >/dev/null 2>&1 && break
  sleep 0.5
done
trap 'stop_server' EXIT
start_server || exit 1
ok "stack up (gateway + control plane)"

say "PHASE 1/10 — live demo A"
bash "$ROOT/scripts/e2e-live.sh" || SUITE_FAIL=1

say "PHASE 2/10 — governance plane"
bash "$ROOT/scripts/governance-e2e.sh" || SUITE_FAIL=1

say "PHASE 3/10 — git workspaces"
bash "$ROOT/scripts/e2e-git-workspace.sh" || SUITE_FAIL=1

say "PHASE 4/10 — api triggers & signed callbacks"
bash "$ROOT/scripts/e2e-trigger.sh" || SUITE_FAIL=1

say "PHASE 5/10 — scheduled borrowing"
stop_server   # the schedule suite owns (and restarts) its own control plane
bash "$ROOT/scripts/e2e-schedule.sh" || SUITE_FAIL=1

say "PHASE 6/10 — github pr-review fan-out"
bash "$ROOT/scripts/e2e-github.sh" || SUITE_FAIL=1

say "PHASE 7/10 — capability & MCP catalog"
bash "$ROOT/scripts/e2e-capabilities.sh" || SUITE_FAIL=1

say "PHASE 8/10 — connector catalog & oauth custody"
bash "$ROOT/scripts/e2e-connectors.sh" || SUITE_FAIL=1

say "PHASE 9/10 — failure paths"
bash "$ROOT/scripts/e2e-failures.sh" || SUITE_FAIL=1

say "PHASE 10/10 — codex (second harness)"
bash "$ROOT/scripts/e2e-codex.sh" || SUITE_FAIL=1

say "E2E RESULT"
if [ "$SUITE_FAIL" = "0" ]; then
  printf "  \033[1;32mALL PHASES PASSED\033[0m\n"
else
  printf "  \033[1;31mFAILURES\033[0m — see phase output above\n"
fi
exit "$SUITE_FAIL"
