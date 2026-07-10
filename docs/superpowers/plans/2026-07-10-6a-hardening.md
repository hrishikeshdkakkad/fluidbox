# 6.A Near-Term Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close HANDOVER.md §6.A — automate the acceptance demos behind `just e2e`, add failure-path coverage (tool-call budget stop, dead-container watchdog, restart orphan sweep, stalled-launch sweep), and resolve PLAN.md §10 decisions #1 (shell-risk classifier) and #3 (seed budgets) with real ledger data.

**Architecture:** Keep the repo's established acceptance style — bash scripts driving real HTTP against the live server + Neon + Docker (`scripts/governance-e2e.sh` house pattern), factored over a shared `scripts/e2e-lib.sh`. One Rust change (stalled-launch sweep: `Created→Failed` edge + db query + watchdog arm) fixes the gap the live DB exposed (2 zombie `created` sessions). One coherence fix makes `policy.budgets` real (today it is parsed and stored but read by nothing).

**Tech Stack:** bash + curl + python3 (JSON), Rust (axum server, sqlx), Docker, Neon Postgres, just.

## Global Constraints

- Backend is 100% Rust; scripts are test tooling, not backend (same standing as `governance-e2e.sh`).
- The server remains the **single status writer**; tests observe, never write status (except the sanctioned psql *fixture injection* for the stalled-launch case, which simulates a crashed control plane).
- RunSpec freeze / append-only agents / redacted ledger invariants (PLAN.md §2) untouched.
- Do not break `governance-e2e.sh` semantics: `Read`→allow, `WebFetch`→deny, `git push origin main`→require-approval must survive the policy tuning.
- `.env` and `apps/web/.env.local` are never committed.
- `FLUIDBOX_BIND` for any server the suite starts must be `0.0.0.0:8787` (sandboxes reach it via `host.docker.internal`).
- Servers started by scripts must run with cwd = repo root (the boot seeder reads `./policies`).
- Quality bar: `just check` (fmt + clippy -D warnings + workspace tests + web build) green at every commit.
- The failure-path and governance suites must not require a model key; only the live demo phase does (and it self-skips without one).

---

### Task 1: Script portability + `.env.example` bind fix

**Files:**
- Modify: `scripts/governance-e2e.sh:6-8` (hardcoded absolute `cd`; stale header claim)
- Modify: `.env.example:8` (loopback bind contradicts the documented gotcha)

**Interfaces:**
- Produces: `governance-e2e.sh` runnable from any checkout path (Task 5 orchestrator relies on this).

- [ ] **Step 1: Make governance-e2e.sh path-independent and fix its header**

Replace lines 1–8:

```bash
#!/usr/bin/env bash
# Governance-plane E2E over real HTTP. Drives the internal gateway with a real
# session token (exactly the runner's contract), proving policy eval,
# approval pause/resume, idempotency, session-scope, and autonomous
# auto-deny — all against the live server + Neon. No model required.
# (Budget/watchdog/restart failure paths live in scripts/e2e-failures.sh.)
set -uo pipefail
cd "$(dirname "$0")/.."
set -a; source .env; set +a
```

- [ ] **Step 2: Fix `.env.example` bind**

Replace the `FLUIDBOX_BIND` block with:

```bash
# Must be 0.0.0.0, not loopback: sandboxes reach the control plane via
# host.docker.internal (the host gateway IP) — a 127.0.0.1 bind is
# unreachable from inside a container.
FLUIDBOX_BIND=0.0.0.0:8787
```

- [ ] **Step 3: Verify** — `bash scripts/governance-e2e.sh` from a different cwd (`cd /tmp && bash <repo>/scripts/governance-e2e.sh`) still runs (requires dev server up; if not up, verify it fails on the health/API step, not on `cd`).

- [ ] **Step 4: Commit** — `fix(scripts): governance e2e runs from any cwd; .env.example uses reachable bind`

---

### Task 2: Stalled-launch sweep (Created/Provisioning/Initializing zombies)

The live DB has 2 sessions stuck in `created` forever: a control-plane death between session insert and provisioning leaves rows no worker watches. `Created` is the only non-terminal state with no edge to `Failed`.

**Files:**
- Modify: `crates/fluidbox-core/src/state.rs:63-82` (add `Created→Failed`) and its tests
- Modify: `crates/fluidbox-db/src/lib.rs` (add `stale_nonstarted_sessions`, add test)
- Modify: `crates/fluidbox-server/src/workers.rs:37-69` (watchdog arm)

**Interfaces:**
- Produces: `pub async fn stale_nonstarted_sessions(pool: &PgPool, max_age_mins: i32) -> sqlx::Result<Vec<SessionRow>>` (Task 3's F4 asserts its effect over HTTP).

- [ ] **Step 1: Failing state-machine test** — in `state.rs` tests add:

```rust
    #[test]
    fn any_nonterminal_state_can_fail() {
        // A crashed control plane must be able to fail a session wherever
        // it was left — Created included (the stalled-launch sweep).
        for s in [Created, Provisioning, Initializing, Running, AwaitingApproval] {
            assert!(s.can_transition_to(Failed), "{s:?} must be able to fail");
        }
    }
```

- [ ] **Step 2: Run** `cargo test -p fluidbox-core state::` — expect FAIL (`Created must be able to fail`).

- [ ] **Step 3: Add the edge** — in `can_transition_to`, add `| (Created, Failed)` after `(Created, Cancelled)`.

- [ ] **Step 4: Run** `cargo test -p fluidbox-core state::` — expect PASS.

- [ ] **Step 5: db helper + integration test** — in `fluidbox-db/src/lib.rs` next to `sessions_in_status`:

```rust
/// Sessions stuck before launch. The orchestrator moves created →
/// provisioning → initializing in seconds (initializing: minutes at worst
/// for a big repo copy), so a stale row means the control plane died
/// mid-launch and nothing owns the session anymore.
pub async fn stale_nonstarted_sessions(
    pool: &PgPool,
    max_age_mins: i32,
) -> sqlx::Result<Vec<SessionRow>> {
    sqlx::query_as(
        "select * from sessions
         where status = any($1) and updated_at < now() - make_interval(mins => $2)",
    )
    .bind(vec![
        "created".to_string(),
        "provisioning".to_string(),
        "initializing".to_string(),
    ])
    .bind(max_age_mins)
    .fetch_all(pool)
    .await
}
```

Test (house self-skip pattern, after the seq test):

```rust
    #[tokio::test]
    async fn stale_nonstarted_sweep_finds_only_old_prelaunch_sessions() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = connect(&url).await.expect("connect");
        let tenant = ensure_default_tenant(&pool).await.unwrap();
        let policy = upsert_policy(&pool, tenant, "test-stale", "name: test-stale",
            &serde_json::json!({"name": "test-stale"})).await.unwrap();
        let agent = create_agent(&pool, tenant, "test-stale-agent", None).await.unwrap();
        let rev = append_agent_revision(&pool, agent.id, "claude-agent-sdk", "img:test",
            "claude-haiku-4-5", None, policy.id, &serde_json::json!({})).await.unwrap();
        let mk = |task: &str| {
            (task.to_string(),)
        };
        let _ = mk; // keep helper-free; create two sessions directly
        let fresh = create_session(&pool, tenant, agent.id, rev.id, "supervised",
            "stale-test fresh", &serde_json::json!({"kind":"none"}),
            &serde_json::json!({}), &serde_json::json!({})).await.unwrap();
        let stale = create_session(&pool, tenant, agent.id, rev.id, "supervised",
            "stale-test old", &serde_json::json!({"kind":"none"}),
            &serde_json::json!({}), &serde_json::json!({})).await.unwrap();
        sqlx::query("update sessions set updated_at = now() - interval '20 minutes' where id = $1")
            .bind(stale.id).execute(&pool).await.unwrap();

        let hits = stale_nonstarted_sessions(&pool, 15).await.unwrap();
        let ids: Vec<Uuid> = hits.iter().map(|s| s.id).collect();
        assert!(ids.contains(&stale.id), "old created session must be swept");
        assert!(!ids.contains(&fresh.id), "fresh session must not be swept");

        // Terminal sessions are never swept even when old.
        transition_session(&pool, stale.id, SessionStatus::Failed, Some("test"))
            .await.unwrap();
        let ids2: Vec<Uuid> = stale_nonstarted_sessions(&pool, 15).await.unwrap()
            .iter().map(|s| s.id).collect();
        assert!(!ids2.contains(&stale.id));

        for id in [fresh.id, stale.id] {
            sqlx::query("delete from sessions where id = $1").bind(id)
                .execute(&pool).await.unwrap();
        }
    }
```

(Adjust `create_session` argument list to the real signature in `lib.rs` when writing — it takes `(pool, tenant, agent_id, agent_revision_id, autonomy, task, repo_source, run_spec, budgets)`.)

- [ ] **Step 6: Run** `set -a; source .env; set +a; cargo test -p fluidbox-db stale_nonstarted` — expect PASS (against real Neon).

- [ ] **Step 7: Watchdog arm** — in `workers.rs`, add a module const and extend the watchdog loop after the heartbeat pass:

```rust
const STALE_LAUNCH_MINS: i32 = 15;
```

```rust
        // Sessions stuck before launch: created/provisioning/initializing
        // are seconds-long states; a stale row means the control plane died
        // mid-launch and nothing owns the session anymore.
        match fluidbox_db::stale_nonstarted_sessions(&state.pool, STALE_LAUNCH_MINS).await {
            Ok(stale) => {
                for s in stale {
                    tracing::warn!(
                        "watchdog: {} stalled in '{}' for >{}m — failing",
                        s.id, s.status, STALE_LAUNCH_MINS
                    );
                    orchestrator::fail(&state, s.id, "stalled before launch (control plane interrupted)")
                        .await;
                }
            }
            Err(e) => tracing::warn!("stale-launch sweep failed: {e}"),
        }
```

- [ ] **Step 8: Full bar** — `cargo clippy --workspace --all-targets -- -D warnings && cargo test -p fluidbox-core && (set -a; source .env; set +a; cargo test -p fluidbox-db)` — PASS.

- [ ] **Step 9: Commit** — `fix(workers): sweep sessions stalled before launch; allow Created→Failed`

---

### Task 3: Shared e2e lib + failure-path suite

**Files:**
- Create: `scripts/e2e-lib.sh`
- Create: `scripts/e2e-failures.sh`

**Interfaces:**
- Consumes: Task 2's sweep (F4), runner contract (`tool.requested` event **then** `/permission` — `tool_call_count` counts `tool.requested` rows, so the emulation must post the event first, exactly like `images/sandbox-runner/runner/index.mjs`).
- Produces: `e2e-lib.sh` sourced by Tasks 4–5 (`ROOT`, `API`, `load_env`, `require_cmd`, `ok/no/say`, `j`, `port_in_use`, `wait_health`, `start_server`, `stop_server`).

- [ ] **Step 1: Write `scripts/e2e-lib.sh`**

```bash
#!/usr/bin/env bash
# Shared helpers for the fluidbox e2e suites. Source, don't execute:
#   source "$(dirname "$0")/e2e-lib.sh"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
API=${FLUIDBOX_API_URL:-http://127.0.0.1:8787}
SERVER_PID=""
SERVER_LOG="${SERVER_LOG:-$(mktemp -t fbx-e2e-server).log}"

pass=0; fail=0
ok()  { printf "  \033[1;32m✓\033[0m %s\n" "$1"; pass=$((pass+1)); }
no()  { printf "  \033[1;31m✗\033[0m %s\n" "$1"; fail=$((fail+1)); }
say() { printf "\n\033[1;36m== %s ==\033[0m\n" "$1"; }

j() { python3 -c "import sys,json;d=json.load(sys.stdin);print(d$1)" 2>/dev/null; }

load_env() {
  [ -f "$ROOT/.env" ] || { echo "missing $ROOT/.env — copy .env.example and fill it in"; exit 1; }
  set -a; source "$ROOT/.env"; set +a
}

require_cmd() {
  for c in "$@"; do
    command -v "$c" >/dev/null 2>&1 || { echo "missing required command: $c"; exit 1; }
  done
}

port_in_use() { curl -fsS -m 2 "$API/health" >/dev/null 2>&1; }

wait_health() { # [tries × 0.5s]
  for _ in $(seq 1 "${1:-120}"); do
    curl -fsS -m 2 "$API/health" >/dev/null 2>&1 && return 0
    sleep 0.5
  done
  return 1
}

# Start a control plane we own. cwd = repo root (the boot seeder reads
# ./policies); bind 0.0.0.0 so sandboxes reach us via host.docker.internal.
start_server() {
  ( cd "$ROOT" && exec env FLUIDBOX_BIND=0.0.0.0:8787 \
      ./target/debug/fluidbox-server >>"$SERVER_LOG" 2>&1 ) &
  SERVER_PID=$!
  if ! wait_health 120; then
    echo "server failed to become healthy; last log lines:"
    tail -20 "$SERVER_LOG"
    return 1
  fi
}

stop_server() {
  [ -n "$SERVER_PID" ] || return 0
  kill "$SERVER_PID" 2>/dev/null
  wait "$SERVER_PID" 2>/dev/null
  SERVER_PID=""
  for _ in $(seq 1 20); do port_in_use || return 0; sleep 0.5; done
  return 0
}
```

- [ ] **Step 2: Write `scripts/e2e-failures.sh`**

```bash
#!/usr/bin/env bash
# Failure-path E2E — the PLAN.md M1 step-12 acceptance list the demos don't
# cover. Owns its control-plane lifecycle (it must restart the server for the
# orphan-sweep case), so it refuses to run when something else holds :8787.
# No model, no gateway, no key needed. Requires: docker, psql, python3, .env.
#
#   F1  max_tool_calls: 2 → third call refused + session budget_exceeded
#   F2  container killed mid-run → watchdog fails + reaps
#   F3  server restart → boot sweep reaps unknown-session orphan, spares the
#       live session's sandbox; cancel then reaps it
#   F4  session stalled in 'created' → stale-launch sweep fails it
set -uo pipefail
source "$(dirname "$0")/e2e-lib.sh"
load_env
require_cmd docker psql python3 curl cargo
H="authorization: Bearer $FLUIDBOX_ADMIN_TOKEN"

if port_in_use; then
  echo "port 8787 already serving — stop 'just dev' first (this suite restarts the control plane)"
  exit 1
fi
echo "building server…"
cargo build -q -p fluidbox-server || exit 1
trap 'stop_server' EXIT
start_server || exit 1

new_session() { # task budgets_json -> session id
  curl -s -X POST -H "$H" -H 'content-type: application/json' \
    -d "{\"agent\":\"claude-fixer\",\"task\":\"$1\",\"repo\":{\"kind\":\"none\"},\"autonomous\":false,\"budgets\":$2}" \
    "$API/v1/sessions" | j "['session']['id']"
}
wait_container() { # session -> container id (running)
  for _ in $(seq 1 60); do
    C=$(docker ps --filter "label=fluidbox.session=$1" --format '{{.ID}}' | head -1)
    [ -n "$C" ] && { echo "$C"; return 0; }
    sleep 0.5
  done
  echo ""
}
token_for() { # container -> session token
  docker inspect "$1" --format '{{range .Config.Env}}{{println .}}{{end}}' \
    | grep '^FLUIDBOX_SESSION_TOKEN=' | head -1 | cut -d= -f2-
}
status_of() { curl -s -H "$H" "$API/v1/sessions/$1" | j "['session']['status']"; }
reason_of() { curl -s -H "$H" "$API/v1/sessions/$1" | j "['session']['status_reason']"; }
wait_status() { # id want tries [sleep]
  for _ in $(seq 1 "$3"); do
    [ "$(status_of "$1")" = "$2" ] && return 0
    sleep "${4:-1}"
  done
  return 1
}
containers_for() { docker ps -a --filter "label=fluidbox.session=$1" -q | wc -l | tr -d ' '; }
# The runner contract: a tool.requested event lands BEFORE /permission —
# tool_call_count counts those events (see runner/index.mjs).
emit_tool_requested() { # token session call_id
  curl -s -X POST -H "authorization: Bearer $1" -H 'content-type: application/json' \
    -d "{\"actor\":\"agent\",\"body\":{\"type\":\"tool.requested\",\"data\":{\"tool_call_id\":\"$3\",\"tool\":\"Read\",\"summary\":\"budget probe\",\"input_digest\":\"\"}}}" \
    "$API/internal/sessions/$2/events" >/dev/null
}
perm() { # token session body -> decision json
  curl -s -X POST -H "authorization: Bearer $1" -H 'content-type: application/json' \
    -d "$3" "$API/internal/sessions/$2/permission"
}

# ── F1: tool-call budget ────────────────────────────────────────────────
say "F1 — max_tool_calls: 2 → third call refused, session budget_exceeded"
S1=$(new_session "budget probe — reply DONE, use no tools" '{"max_tool_calls":2}')
[ -n "$S1" ] && ok "session created ($S1)" || { no "session create failed"; exit 1; }
C1=$(wait_container "$S1")
[ -n "$C1" ] && ok "sandbox launched" || { no "no sandbox"; exit 1; }
T1=$(token_for "$C1")
docker kill "$C1" >/dev/null 2>&1   # silence the real runner; the script IS the runner now
for i in 1 2 3; do
  emit_tool_requested "$T1" "$S1" "bp$i"
  D=$(perm "$T1" "$S1" "{\"tool_call_id\":\"bp$i\",\"tool\":\"Read\",\"input\":{\"file_path\":\"/workspace/f$i\"}}")
  DEC=$(echo "$D" | j "['decision']")
  if [ "$i" -le 2 ]; then
    [ "$DEC" = "allow" ] && ok "call $i → allow (within budget)" || no "call $i expected allow, got $DEC"
  else
    [ "$DEC" = "deny" ] && ok "call 3 → deny (budget gate)" || no "call 3 expected deny, got $DEC"
    echo "$D" | j "['message']" | grep -q "budget" && ok "deny message names the budget" || no "deny message: $(echo "$D" | j "['message']")"
  fi
done
wait_status "$S1" budget_exceeded 30 1 \
  && ok "session → budget_exceeded" || no "expected budget_exceeded, got $(status_of "$S1")"
NBE=$(curl -s -H "$H" "$API/v1/sessions/$S1/events?limit=200" | python3 -c "
import sys, json
evs = json.load(sys.stdin)['events']
print(sum(1 for e in evs if e['type'] == 'budget.exceeded'
          and e['payload']['data'].get('budget') == 'max_tool_calls'))")
[ "$NBE" -ge 1 ] 2>/dev/null && ok "budget.exceeded ledgered" || no "no budget.exceeded event"

# ── F2: dead container → watchdog ───────────────────────────────────────
say "F2 — kill container mid-run → watchdog fails + reaps (≤ ~90s)"
S2=$(new_session "watchdog probe — reply DONE, use no tools" '{}')
C2=$(wait_container "$S2")
[ -n "$C2" ] && ok "sandbox launched" || { no "no sandbox"; exit 1; }
wait_status "$S2" running 20 0.5 || true
docker kill "$C2" >/dev/null 2>&1
ok "container killed while session running"
wait_status "$S2" failed 150 1 \
  && ok "watchdog failed the session" || no "expected failed, got $(status_of "$S2")"
reason_of "$S2" | grep -qi "heartbeat" \
  && ok "reason names the stale heartbeat" || no "reason: $(reason_of "$S2")"
[ "$(containers_for "$S2")" = "0" ] \
  && ok "sandbox reaped" || no "container still present"

# ── F3: restart → boot orphan sweep ─────────────────────────────────────
say "F3 — restart: orphan reaped, live session's sandbox spared"
S3=$(new_session "restart probe — reply DONE, use no tools" '{}')
C3=$(wait_container "$S3")
[ -n "$C3" ] && ok "live session sandbox up" || { no "no sandbox"; exit 1; }
docker kill "$C3" >/dev/null 2>&1   # freeze it: container stays (Exited), no completion race
BOGUS_SID=$(python3 -c 'import uuid; print(uuid.uuid4())')
BOGUS=$(docker run -d --label fluidbox.managed=1 --label "fluidbox.session=$BOGUS_SID" \
  --entrypoint sleep "$FLUIDBOX_SANDBOX_IMAGE" 600)
ok "planted orphan container (unknown session $BOGUS_SID)"
stop_server
start_server || exit 1              # boot_orphan_sweep runs before the port opens
if [ -z "$(docker ps -aq --no-trunc --filter "id=$BOGUS")" ]; then
  ok "boot sweep reaped the unknown-session orphan"
else
  no "orphan container survived the boot sweep"
  docker rm -f "$BOGUS" >/dev/null 2>&1
fi
[ "$(containers_for "$S3")" = "1" ] \
  && ok "live session's sandbox spared by the sweep" || no "live sandbox was reaped"
[ "$(status_of "$S3")" = "running" ] \
  && ok "session still running after restart" || no "session status: $(status_of "$S3")"
curl -s -X POST -H "$H" "$API/v1/sessions/$S3/cancel" >/dev/null
for _ in $(seq 1 15); do [ "$(containers_for "$S3")" = "0" ] && break; sleep 1; done
[ "$(containers_for "$S3")" = "0" ] \
  && ok "cancel reaped the sandbox" || no "sandbox not reaped after cancel"

# ── F4: stalled-launch sweep ────────────────────────────────────────────
say "F4 — session stalled in 'created' → stale-launch sweep fails it"
S4=$(psql "$DATABASE_URL" -tA -c "
  insert into sessions (id, tenant_id, agent_id, agent_revision_id, status, autonomy,
                        trust_tier, task, repo_source, run_spec, budgets, created_at, updated_at)
  select gen_random_uuid(), tenant_id, agent_id, agent_revision_id, 'created', 'supervised',
         'trusted', 'fbx-e2e stale probe', repo_source, run_spec, budgets,
         now() - interval '30 minutes', now() - interval '30 minutes'
  from sessions where id = '$S3'
  returning id;")
[ -n "$S4" ] && ok "injected stalled 'created' session ($S4)" || { no "fixture insert failed"; exit 1; }
wait_status "$S4" failed 30 1 \
  && ok "stale-launch sweep failed it" || no "expected failed, got $(status_of "$S4")"
reason_of "$S4" | grep -qi "stalled before launch" \
  && ok "reason names the stall" || no "reason: $(reason_of "$S4")"

say "RESULT"
printf "  \033[1;32m%d passed\033[0m, \033[1;31m%d failed\033[0m\n" "$pass" "$fail"
exit $(( fail > 0 ? 1 : 0 ))
```

- [ ] **Step 3: chmod +x both scripts.**

- [ ] **Step 4: Run** `bash scripts/e2e-failures.sh` with `just dev` stopped — expect all checks green in ~3 minutes (F2 dominates: 60s stale + ≤15s tick). Any red check = a real bug → switch to superpowers:systematic-debugging before touching the test.

- [ ] **Step 5: Commit** — `test(e2e): failure-path suite — budget stop, watchdog, restart sweeps`

---

### Task 4: Live demo A automation

**Files:**
- Create: `scripts/e2e-live.sh`

**Interfaces:**
- Consumes: `e2e-lib.sh`; CLI binary `target/debug/fluidbox` (prints `▶ session <id>`); `GET /v1/sessions/{id}` (`session.status`), `/artifacts` (`kind == "diff"`, `artifact.content`), `/cost` (`usage.cost_usd`, `tool_calls`).
- Fixture mirrors the proven live demo (ledger shows `python3 -m unittest -v` + `Edit /workspace/calculator.py`), so the default policy allows every expected tool.

- [ ] **Step 1: Write `scripts/e2e-live.sh`**

```bash
#!/usr/bin/env bash
# Acceptance demo A, automated: a live agent finds and fixes a failing unit
# test in a governed sandbox. Asserts completed + diff + cost + isolation.
# Self-skips without a key or gateway (exit 0) so the suite stays runnable
# offline; set E2E_SKIP_LIVE=1 to skip explicitly.
set -uo pipefail
source "$(dirname "$0")/e2e-lib.sh"
load_env
require_cmd docker python3 curl git cargo
H="authorization: Bearer $FLUIDBOX_ADMIN_TOKEN"

if [ "${E2E_SKIP_LIVE:-0}" = "1" ]; then
  echo "  SKIP: E2E_SKIP_LIVE=1"; exit 0
fi
if [ -z "${ANTHROPIC_API_KEY:-}" ]; then
  echo "  SKIP: no ANTHROPIC_API_KEY in .env (the gateway needs it for live runs)"; exit 0
fi
if ! curl -fsS -m 3 http://127.0.0.1:4000/health/liveliness >/dev/null 2>&1; then
  echo "  SKIP: LiteLLM gateway not reachable on :4000 (just gateway-up)"; exit 0
fi

OWN_SERVER=0
if ! port_in_use; then
  cargo build -q -p fluidbox-server || exit 1
  trap 'stop_server' EXIT
  start_server || exit 1
  OWN_SERVER=1
fi

say "DEMO A — live agent fixes a failing test"
TMP_REPO=$(mktemp -d -t fbx-demoa)
cat > "$TMP_REPO/calculator.py" <<'EOF'
def add(a, b):
    return a + b


def multiply(a, b):
    return a + b
EOF
cat > "$TMP_REPO/test_calculator.py" <<'EOF'
import unittest

from calculator import add, multiply


class TestCalculator(unittest.TestCase):
    def test_add(self):
        self.assertEqual(add(2, 3), 5)

    def test_multiply(self):
        self.assertEqual(multiply(2, 3), 6)
        self.assertEqual(multiply(4, 5), 20)


if __name__ == "__main__":
    unittest.main()
EOF
git -C "$TMP_REPO" init -q
git -C "$TMP_REPO" add -A
git -C "$TMP_REPO" -c user.email=e2e@fluidbox.dev -c user.name=fbx-e2e commit -qm fixture
ORIG_SHA=$(git -C "$TMP_REPO" rev-parse HEAD)

cargo build -q -p fluidbox-cli || exit 1
OUT=$("$ROOT/target/debug/fluidbox" run --agent claude-fixer \
  --task "The unit tests fail. Run python3 -m unittest -v to see the failure, fix the bug in the source file, then re-run python3 -m unittest -v and confirm everything passes." \
  --repo "$TMP_REPO" --detach)
echo "  $OUT"
S=$(echo "$OUT" | sed -n 's/.*session \([0-9a-f-]\{36\}\).*/\1/p')
[ -n "$S" ] && ok "run started from the CLI (session $S)" || { no "no session id in CLI output"; exit 1; }

FINAL=""
DEADLINE=$(( $(date +%s) + 420 ))
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
  ST=$(status_of=$(curl -s -H "$H" "$API/v1/sessions/$S" | j "['session']['status']"); echo "$status_of")
  case "$ST" in
    completed|failed|cancelled|budget_exceeded) FINAL=$ST; break ;;
    awaiting_approval)
      PEND=$(curl -s -H "$H" "$API/v1/sessions/$S/approvals" | python3 -c "
import sys, json
a = [x for x in json.load(sys.stdin)['approvals'] if x['status'] == 'pending']
print(a[0]['summary'] if a else '')")
      no "agent paused for approval — demo A expects none. Pending: '$PEND' (policy allow_prefixes candidate?)"
      curl -s -X POST -H "$H" "$API/v1/sessions/$S/cancel" >/dev/null
      exit 1 ;;
  esac
  sleep 5
done
if [ "$FINAL" = "completed" ]; then
  ok "session completed"
else
  no "terminal state: ${FINAL:-timeout-after-420s} (wanted completed)"
  echo "  last events:"
  curl -s -H "$H" "$API/v1/sessions/$S/events?limit=200" | python3 -c "
import sys, json
for e in json.load(sys.stdin)['events'][-8:]:
    print('   ', e['type'], json.dumps(e['payload']['data'])[:140])"
  exit 1
fi

AID=$(curl -s -H "$H" "$API/v1/sessions/$S/artifacts" | python3 -c "
import sys, json
d = [a for a in json.load(sys.stdin)['artifacts'] if a['kind'] == 'diff']
print(d[0]['id'] if d else '')")
[ -n "$AID" ] && ok "diff artifact present" || no "no diff artifact"
PATCH=$(curl -s -H "$H" "$API/v1/sessions/$S/artifacts/$AID" | j "['artifact']['content']")
echo "$PATCH" | grep -q "calculator.py" && ok "diff touches calculator.py" || no "diff does not touch calculator.py"
echo "$PATCH" | grep -q 'a \* b' && ok "diff contains the multiply fix" || no "diff lacks 'a * b': $(echo "$PATCH" | head -3)"

COST=$(curl -s -H "$H" "$API/v1/sessions/$S/cost" | j "['usage']['cost_usd']")
python3 -c "import sys; sys.exit(0 if float('${COST:-0}' or 0) > 0 else 1)" \
  && ok "cost ledgered (\$${COST})" || no "no cost recorded (gateway usage callback broken?)"
TOOLS=$(curl -s -H "$H" "$API/v1/sessions/$S/cost" | j "['tool_calls']")
[ "${TOOLS:-0}" -ge 1 ] 2>/dev/null && ok "tool calls ledgered ($TOOLS)" || no "no tool.requested events"

[ -z "$(git -C "$TMP_REPO" status --porcelain)" ] && [ "$(git -C "$TMP_REPO" rev-parse HEAD)" = "$ORIG_SHA" ] \
  && ok "original repo untouched (isolation)" || no "ORIGINAL REPO WAS MODIFIED"
grep -q "return a + b" "$TMP_REPO/calculator.py" \
  && ok "original still has the bug (agent worked on the copy)" || no "original source changed"

say "RESULT"
printf "  \033[1;32m%d passed\033[0m, \033[1;31m%d failed\033[0m\n" "$pass" "$fail"
exit $(( fail > 0 ? 1 : 0 ))
```

(Note: fix the `ST=` line when writing — it should be plainly `ST=$(curl -s -H "$H" "$API/v1/sessions/$S" | j "['session']['status']")`.)

- [ ] **Step 2: chmod +x; run** `bash scripts/e2e-live.sh` with gateway up + key present — expect green in ~1–3 min (haiku).

- [ ] **Step 3: Commit** — `test(e2e): automate acceptance demo A (live agent, diff, cost, isolation)`

---

### Task 5: `scripts/e2e.sh` orchestrator + `just e2e` + `just policy-sync`

**Files:**
- Create: `scripts/e2e.sh`
- Create: `scripts/policy-sync.sh`
- Modify: `justfile` (new recipes)
- Modify: `CLAUDE.md` commands block (one line for `just e2e`)

**Interfaces:**
- Consumes: all three phase scripts; `deploy/docker-compose.dev.yml` (gateway); `POST /v1/policies` (sync).

- [ ] **Step 1: Write `scripts/e2e.sh`**

```bash
#!/usr/bin/env bash
# `just e2e` — the one-command acceptance suite:
#   phase 1: live demo A        (real model; self-skips without key/gateway)
#   phase 2: governance plane   (policy, approvals, autonomy — no model)
#   phase 3: failure paths      (budget stop, watchdog, restart — no model)
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
if ! docker image inspect "$FLUIDBOX_SANDBOX_IMAGE" >/dev/null 2>&1; then
  echo "building sandbox image $FLUIDBOX_SANDBOX_IMAGE…"
  docker build -t "$FLUIDBOX_SANDBOX_IMAGE" "$ROOT/images/sandbox-runner" || exit 1
fi
echo "building server + cli…"
cargo build -q -p fluidbox-server -p fluidbox-cli || exit 1
docker compose -f "$ROOT/deploy/docker-compose.dev.yml" up -d litellm >/dev/null 2>&1 || true
for _ in $(seq 1 40); do
  curl -fsS -m 2 http://127.0.0.1:4000/health/liveliness >/dev/null 2>&1 && break
  sleep 0.5
done
trap 'stop_server' EXIT
start_server || exit 1
ok "stack up (gateway + control plane)"

say "PHASE 1/3 — live demo A"
bash "$ROOT/scripts/e2e-live.sh" || SUITE_FAIL=1

say "PHASE 2/3 — governance plane"
bash "$ROOT/scripts/governance-e2e.sh" || SUITE_FAIL=1

say "PHASE 3/3 — failure paths"
stop_server   # the failure suite owns (and restarts) its own control plane
bash "$ROOT/scripts/e2e-failures.sh" || SUITE_FAIL=1

say "E2E RESULT"
if [ "$SUITE_FAIL" = "0" ]; then
  printf "  \033[1;32mALL PHASES PASSED\033[0m\n"
else
  printf "  \033[1;31mFAILURES\033[0m — see phase output above\n"
fi
exit "$SUITE_FAIL"
```

- [ ] **Step 2: Write `scripts/policy-sync.sh`**

```bash
#!/usr/bin/env bash
# Push policies/*.yaml to the control plane (POST /v1/policies → version++).
# Boot seeding is insert-if-absent by design (UI edits win on reboot); this
# is the explicit "disk is truth" operator action. In-flight runs keep their
# frozen policy snapshot — only future runs pick the new version up.
set -euo pipefail
cd "$(dirname "$0")/.."
set -a; source .env; set +a
export FLUIDBOX_API_URL=${FLUIDBOX_API_URL:-http://127.0.0.1:8787}
for f in policies/*.yaml; do
  python3 - "$f" <<'EOF'
import json, os, pathlib, sys, urllib.request

path = pathlib.Path(sys.argv[1])
yaml = path.read_text()
name = next(l.split(":", 1)[1].strip() for l in yaml.splitlines() if l.startswith("name:"))
req = urllib.request.Request(
    os.environ["FLUIDBOX_API_URL"] + "/v1/policies",
    data=json.dumps({"name": name, "yaml": yaml}).encode(),
    headers={
        "authorization": "Bearer " + os.environ["FLUIDBOX_ADMIN_TOKEN"],
        "content-type": "application/json",
    },
    method="POST",
)
with urllib.request.urlopen(req) as r:
    policy = json.load(r)["policy"]
print(f"  ✓ {name} → version {policy['version']}")
EOF
done
```

- [ ] **Step 3: justfile recipes** (after the Quality section)

```make
# ── E2E acceptance ───────────────────────────────────────────────────────

# Full acceptance suite: live demo A + governance plane + failure paths.
# Owns the stack (requires :8787 free). The live phase self-skips without
# ANTHROPIC_API_KEY; E2E_SKIP_LIVE=1 skips it explicitly.
e2e:
    bash scripts/e2e.sh

# Push policies/*.yaml to the running control plane (bumps policy version;
# in-flight runs keep their frozen snapshot).
policy-sync:
    bash scripts/policy-sync.sh
```

- [ ] **Step 4: CLAUDE.md commands block** — add under `just check`:

```
just e2e            # full acceptance: live demo A + governance + failure paths (owns the stack)
```

- [ ] **Step 5: Run** `just e2e` end-to-end (stop `just dev` first) — all three phases green.

- [ ] **Step 6: Commit** — `test(e2e): one-command acceptance suite behind just e2e`

---

### Task 6: Resolve PLAN.md §10 #1 + #3 — shell classifier + real budgets

Ledger data (2026-07-10, 3 completed live runs): cost $0.046–$0.371, tokens 34k–231k (incl. cache), ≤7 model calls, ≤4 tool calls per run; observed commands `python3 -m unittest -v`, `python -m unittest -v 2>&1`, `Edit /workspace/calculator.py`.

**Files:**
- Modify: `policies/default.yaml` (classifier + budgets + rationale comments)
- Modify: `crates/fluidbox-server/src/api.rs:233-237` (policy budgets become a real ceiling)
- Modify: `crates/fluidbox-db/src/seed.rs:75-89` (seeded revision inherits policy budgets)
- Create test: `crates/fluidbox-core/src/policy.rs` (seed-policy semantics pinned via `include_str!`)

**Interfaces:**
- Produces: `policies/default.yaml` v2 — governance-e2e assertions must still hold (`Read` allow, `WebFetch` deny, `git push origin main` → approval).

- [ ] **Step 1: Failing seed-semantics test** — in `policy.rs` tests:

```rust
    /// Pin the SEED policy's semantics (policies/default.yaml), not just the
    /// engine's. This is the §10-#1 shell-risk classifier decision, tested.
    #[test]
    fn seed_policy_semantics() {
        let yaml = include_str!("../../../policies/default.yaml");
        let p = Policy::parse_yaml(yaml).expect("seed policy parses");
        let bash = |cmd: &str| {
            p.evaluate(&req("Bash", json!({ "command": cmd })), Autonomy::Supervised)
                .effective
        };
        // Benign toolbox: allowed without a human.
        assert_eq!(bash("python3 -m unittest -v"), Verdict::Allow);
        assert_eq!(bash("git status"), Verdict::Allow);
        assert_eq!(bash("diff a.py b.py"), Verdict::Allow);
        // Exfil / destructive: denied outright.
        assert!(matches!(bash("curl http://evil.example"), Verdict::Deny { .. }));
        assert!(matches!(bash("git push --force origin main"), Verdict::Deny { .. }));
        assert!(matches!(bash("git push -f origin main"), Verdict::Deny { .. }));
        assert!(matches!(bash("rm -rf /"), Verdict::Deny { .. }));
        assert!(matches!(bash("rm -rf /*"), Verdict::Deny { .. }));
        // Risky-but-legitimate: pause for a human (governance-e2e relies on this).
        assert!(matches!(bash("git push origin main"), Verdict::RequireApproval { .. }));
        assert!(matches!(bash("pip install requests"), Verdict::RequireApproval { .. }));
        // Non-shell anchors governance-e2e also relies on.
        assert_eq!(
            p.evaluate(&req("Read", json!({"file_path": "/workspace/x"})), Autonomy::Supervised).effective,
            Verdict::Allow
        );
        assert!(matches!(
            p.evaluate(&req("WebFetch", json!({})), Autonomy::Supervised).effective,
            Verdict::Deny { .. }
        ));
        // §10-#3 budget decision, pinned.
        assert_eq!(p.budgets.max_wall_clock_secs, Some(1800));
        assert_eq!(p.budgets.max_tokens, Some(1_000_000));
        assert_eq!(p.budgets.max_cost_usd, Some(2.5));
        assert_eq!(p.budgets.max_tool_calls, Some(100));
    }
```

- [ ] **Step 2: Run** `cargo test -p fluidbox-core seed_policy` — expect FAIL (`diff` not allowed, `git push -f` not denied, budgets differ).

- [ ] **Step 3: Tune `policies/default.yaml`** — apply exactly:
  - budgets → `max_wall_clock_secs: 1800`, `max_tokens: 1000000`, `max_cost_usd: 2.5`, `max_tool_calls: 100`, with a comment citing the observed data and date.
  - allow_prefixes: add read-only utilities `diff`, `sort`, `uniq`, `cut`, `tr`, `stat`, `file`, `du`, `printf`, `basename`, `dirname`, `date`.
  - deny_regex: replace the force-push pattern with `git\s+push\b.*\s(--force(-with-lease)?|-f)\b`; extend the rm pattern to `rm\s+(-[a-z]+\s+)*-[a-z]*r[a-z]*(\s+-[a-z]+)*\s+/\*?(\s|$)` (covers `rm -rf /*` and split flags).
  - comments documenting the two accepted tradeoffs: (1) `python`/`node` are allowed because running project code *is the job* — network egress from inside them is the sandbox network mode's boundary, not the classifier's; (2) shell redirection can write files past the Edit/Write path globs — the workspace is a disposable copy, the sandbox is the real boundary.

- [ ] **Step 4: Run** `cargo test -p fluidbox-core` — expect PASS (seed test + existing engine tests).

- [ ] **Step 5: Make policy budgets real** — in `api.rs` `create_session`:

```rust
    let agent_budgets: Budgets = serde_json::from_value(rev.budgets.clone()).unwrap_or_default();
    // The policy's budgets are a ceiling: revision defaults and per-run
    // requests may only tighten below them, never widen past them.
    let ceiling = agent_budgets.tightened_by(&policy.budgets);
    let effective_budgets = match &req.budgets {
        Some(b) => ceiling.tightened_by(b),
        None => ceiling,
    };
```

And in `seed.rs`, seed the curated agent's revision budgets from the default policy instead of `Budgets::default()` (parse the seeded default policy's `budgets`).

- [ ] **Step 6: Apply to the live deployment** — server running → `just policy-sync` (default → version++). Then rerun `bash scripts/governance-e2e.sh` — 14/14 must still pass (proves the tuning preserved the anchor semantics).

- [ ] **Step 7: PLAN.md §10** — mark #1 and #3 resolved:

```markdown
1. ~~`fluidbox-core` policy engine — the shell-command risk classifier~~ **Resolved 2026-07-10** from live-run ledger data: see `policies/default.yaml` (rationale in comments) and the `seed_policy_semantics` test pinning it.
3. ~~Default budget numbers for the seed policy~~ **Resolved 2026-07-10**: 1800s / 1M tokens / $2.50 / 100 tool calls (observed real runs: ≤$0.38, ≤231k tokens, ≤4 tool calls — caps sit 4–25× above observed with the policy now enforced as a ceiling at session creation).
```

- [ ] **Step 8: Commit** — `policy: resolve §10 shell classifier + seed budgets from live-run data; policy budgets now a real ceiling`

---

### Task 7: Full verification + handover update

- [ ] **Step 1:** `just check` — fmt, clippy -D warnings, workspace tests, web build: all green.
- [ ] **Step 2:** `just e2e` — all three phases green (live phase included; key present).
- [ ] **Step 3:** Update `docs/HANDOVER.md`: §1 quality-bar numbers, mark §6.A done (what shipped, where), note `just e2e` in §5.
- [ ] **Step 4: Commit** — `docs: handover — 6.A hardening shipped (e2e suite, failure paths, policy decisions)`

## Self-Review

- **Spec coverage:** 6.A.1 → Tasks 4+5 (`just e2e` wrapping demo A + governance). 6.A.2 → Tasks 2+3 (all three PLAN'd failure paths + the newly-found stalled-launch gap). 6.A.3 → Task 6 (both §10 decisions, data-grounded, with the dead-config budget fix). ✓
- **Placeholders:** none — full script bodies, full Rust snippets, exact commands. (One inline note flags a syntax slip to fix while writing `e2e-live.sh`.) ✓
- **Type consistency:** `stale_nonstarted_sessions(pool, i32)` used identically in Task 2 test and workers; `tightened_by` chain matches `spec.rs`; JSON field names (`artifact.content`, `usage.cost_usd`, `session.status_reason`) verified against `ArtifactRow`/`UsageTotals`/`SessionRow`. ✓
