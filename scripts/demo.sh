#!/usr/bin/env bash
# The five-minute fluidbox demo: a full governed run, no API key required.
#
#   just demo        (= scripts/demo.sh up)   start everything, replay a run,
#                                             pause for YOUR approval, print
#                                             the diff + cost + security receipt
#   just demo-down   (= scripts/demo.sh down) stop + remove every demo resource
#   scripts/demo.sh purge                     down + remove the replay image
#
# What it runs is a DETERMINISTIC REPLAY — a scripted agent driving the real
# control plane, the real policy gate, a real sandbox container, and a real
# diff/cost report. No model calls are made, which is why no key is needed.
# Every resource is demo-scoped (compose project `fluidbox-demo`, port 19790,
# Postgres on 15434 with its own volume, state under .demo/) so a running
# `just dev` stack is never touched.
#
# Knobs (env): FLUIDBOX_DEMO_PORT=19790  FLUIDBOX_DEMO_INTERNAL_PORT=19791
#   FLUIDBOX_DEMO_DB_PORT=15434  FLUIDBOX_REPLAY_IMAGE=fluidbox-replay-runner:dev
#   FLUIDBOX_DEMO_SERVER_BIN=<prebuilt server binary>
#   FLUIDBOX_DEMO_DECISION=approve|deny   (answer the approval non-interactively)
#   FLUIDBOX_DEMO_KEEP=1                  (leave the stack up at the end)
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEMO_DIR="$ROOT/.demo"
PORT="${FLUIDBOX_DEMO_PORT:-19790}"
INTERNAL_PORT="${FLUIDBOX_DEMO_INTERNAL_PORT:-19791}"
DB_PORT="${FLUIDBOX_DEMO_DB_PORT:-15434}"
REPLAY_IMAGE="${FLUIDBOX_REPLAY_IMAGE:-fluidbox-replay-runner:dev}"
API="http://127.0.0.1:$PORT"
COMPOSE=(docker compose -p fluidbox-demo -f "$ROOT/deploy/docker-compose.demo.yml")

BOLD=$'\033[1m'; DIM=$'\033[2m'; RED=$'\033[1;31m'; GREEN=$'\033[1;32m'
YELLOW=$'\033[1;33m'; CYAN=$'\033[1;36m'; RESET=$'\033[0m'
say()  { printf "\n%s== %s ==%s\n" "$CYAN" "$1" "$RESET"; }
ok()   { printf "  %s✓%s %s\n" "$GREEN" "$RESET" "$1"; }
warn() { printf "  %s⚠%s %s\n" "$YELLOW" "$RESET" "$1"; }
die()  { printf "  %s✗ %s%s\n" "$RED" "$1" "$RESET"; shift || true; for l in "$@"; do printf "    %s\n" "$l"; done; exit 1; }

# ── teardown ─────────────────────────────────────────────────────────────
demo_down() {
  say "demo teardown"
  if [ -f "$DEMO_DIR/server.pid" ]; then
    local pid; pid=$(cat "$DEMO_DIR/server.pid" 2>/dev/null || true)
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null; for _ in $(seq 1 20); do kill -0 "$pid" 2>/dev/null || break; sleep 0.25; done
      kill -9 "$pid" 2>/dev/null || true
      ok "control plane stopped (pid $pid)"
    fi
  fi
  # Belt and braces: an interrupted run can lose the pidfile (it lives in
  # .demo/) while the disowned server survives. Reap a listener on the demo
  # port ONLY if it is verifiably OUR fluidbox-server — the argv must point
  # into this checkout (or the explicit override binary). A machine running
  # several fluidbox checkouts can have a NEIGHBOR's server on any port;
  # killing that would sabotage someone else's session, so a foreign listener
  # is left alone (preflight will name it and refuse instead).
  local lpid largv
  for lpid in $(lsof -nP -tiTCP:"$PORT" -sTCP:LISTEN 2>/dev/null); do
    largv=$(ps -o command= -p "$lpid" 2>/dev/null || true)
    if printf '%s' "$largv" | grep -q "fluidbox-server" \
       && { printf '%s' "$largv" | grep -qF "$ROOT/" \
            || { [ -n "${FLUIDBOX_DEMO_SERVER_BIN:-}" ] && printf '%s' "$largv" | grep -qF "$FLUIDBOX_DEMO_SERVER_BIN"; }; }; then
      kill "$lpid" 2>/dev/null; sleep 0.5; kill -9 "$lpid" 2>/dev/null || true
      ok "reaped orphaned demo control plane (pid $lpid on port $PORT)"
    fi
  done
  local strays
  strays=$(docker ps -aq --filter "ancestor=$REPLAY_IMAGE" 2>/dev/null || true)
  if [ -n "$strays" ]; then docker rm -f $strays >/dev/null 2>&1 && ok "removed leftover demo sandbox container(s)"; fi
  if "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1; then
    ok "demo Postgres + volume removed"
  fi
  if [ -d "$DEMO_DIR" ]; then rm -rf "$DEMO_DIR"; ok "removed $DEMO_DIR"; fi
  ok "nothing demo-related is left running"
}

demo_purge() {
  demo_down
  docker rmi "$REPLAY_IMAGE" >/dev/null 2>&1 && ok "removed image $REPLAY_IMAGE" || true
}

# ── preflight ────────────────────────────────────────────────────────────
need_cmd() { command -v "$1" >/dev/null 2>&1 || die "missing required command: $1" "$2"; }

port_free() { # port, what, override-hint
  local out
  out=$(lsof -nP -iTCP:"$1" -sTCP:LISTEN 2>/dev/null | tail -n +2 | head -2)
  [ -z "$out" ] && return 0
  die "port $1 (needed for $2) is already in use:" "$out" \
      "Free it, or pick another port: $3=<port> just demo"
}

# Make the docker CLI and the control plane talk to the SAME daemon.
#
# They resolve it differently and that difference has already cost a run: the
# CLI honors `docker context` (colima/OrbStack/Desktop each install one), while
# the server's docker client is bollard, which reads DOCKER_HOST and otherwise
# falls back to /var/run/docker.sock — it does not know contexts exist. So on a
# machine whose active context is not the default socket, `docker info` passes
# against one daemon and the run then fails against another with
# "No such image: fluidbox-replay-runner:dev". Preflight was validating a
# daemon the server never used.
#
# Resolving once and EXPORTING it removes the class: every docker CLI call in
# this script, `docker compose`, and the server all inherit the same endpoint.
resolve_docker_endpoint() {
  if [ -n "${DOCKER_HOST:-}" ]; then
    ok "docker endpoint: $DOCKER_HOST ${DIM}(from DOCKER_HOST)${RESET}"
    return 0
  fi
  local ctx ep
  ctx=$(docker context show 2>/dev/null || echo default)
  ep=$(docker context inspect "$ctx" --format '{{.Endpoints.docker.Host}}' 2>/dev/null || true)
  if [ -n "$ep" ]; then
    export DOCKER_HOST="$ep"
    ok "docker endpoint: $ep ${DIM}(adopted from docker context '$ctx' — the server's client does not read contexts)${RESET}"
  else
    ok "docker endpoint: default socket ${DIM}(no context override)${RESET}"
  fi
}

preflight() {
  say "preflight (no API key required — this demo is a deterministic replay)"
  need_cmd docker "Install Docker Desktop, OrbStack, or colima."
  docker info >/dev/null 2>&1 || die "Docker is not running." \
      "Start Docker Desktop (or \`colima start\`), wait for it to be ready, then re-run \`just demo\`."
  ok "docker daemon reachable"
  resolve_docker_endpoint
  # Re-check against the endpoint the SERVER will use, which after the resolve
  # above is the same one — this catches a DOCKER_HOST that points somewhere
  # dead while the CLI context is healthy.
  docker info >/dev/null 2>&1 || die "the resolved docker endpoint is not reachable: ${DOCKER_HOST:-default socket}" \
      "This is the endpoint the fluidbox control plane will use." \
      "Either start that daemon, or export DOCKER_HOST to a live one and re-run."
  need_cmd curl "It ships with macOS; on Linux: apt/dnf install curl."
  need_cmd python3 "It ships with macOS; on Linux: apt/dnf install python3."
  need_cmd git "The control plane snapshots workspaces with git."
  if [ -f "$DEMO_DIR/server.pid" ] && kill -0 "$(cat "$DEMO_DIR/server.pid")" 2>/dev/null; then
    die "a demo is already running (pid $(cat "$DEMO_DIR/server.pid"))." \
        "Run \`just demo-down\` first, then \`just demo\` again."
  fi
  # A previous run that died uncleanly: converge to a clean slate first.
  if [ -d "$DEMO_DIR" ] || docker ps -aq --filter "ancestor=$REPLAY_IMAGE" 2>/dev/null | grep -q .; then
    warn "sweeping leftovers from a previous demo"
    demo_down >/dev/null
  fi
  port_free "$PORT" "the fluidbox API" FLUIDBOX_DEMO_PORT
  port_free "$INTERNAL_PORT" "the internal gateway" FLUIDBOX_DEMO_INTERNAL_PORT
  port_free "$DB_PORT" "the demo Postgres" FLUIDBOX_DEMO_DB_PORT
  ok "ports $PORT/$INTERNAL_PORT/$DB_PORT are free"
}

# ── server binary ────────────────────────────────────────────────────────
# Sets the global SERVER_BIN. It does NOT print the path.
#
# It used to `echo` the path and be called as `BIN=$(server_bin)`, which was
# broken on the one path that matters most: a genuinely fresh clone. `warn`, `ok`
# and `die` all print to STDOUT, so on the from-source branch the command
# substitution captured the "first run: compiling the control plane" line AND the
# path, and the launcher then tried to exec that whole multi-line string as a
# command name — "No such file or directory", after a successful build, with the
# real diagnostic swallowed into the variable. `die` was invisible for the same
# reason, and being inside `$( )` its `exit 1` only left the subshell.
#
# The from-source branch is exactly the branch every new user takes, and it was
# missed because the validation drills all set FLUIDBOX_DEMO_SERVER_BIN, whose
# early return prints nothing. A global has no stream to pollute.
resolve_server_bin() {
  if [ -n "${FLUIDBOX_DEMO_SERVER_BIN:-}" ]; then
    [ -x "$FLUIDBOX_DEMO_SERVER_BIN" ] || die "FLUIDBOX_DEMO_SERVER_BIN is not executable: $FLUIDBOX_DEMO_SERVER_BIN"
    SERVER_BIN="$FLUIDBOX_DEMO_SERVER_BIN"; return
  fi
  if [ ! -x "$ROOT/target/debug/fluidbox-server" ]; then
    need_cmd cargo "Install Rust via https://rustup.rs — the demo builds the control plane from source."
    warn "first run: compiling the control plane (one-time; later runs skip this — expect a few minutes)"
    (cd "$ROOT" && cargo build -p fluidbox-server) || die "cargo build failed" "Fix the build error above and re-run."
  fi
  SERVER_BIN="$ROOT/target/debug/fluidbox-server"
  [ -x "$SERVER_BIN" ] || die "the control plane binary is missing after a successful build: $SERVER_BIN" \
      "Re-run, or build it yourself: cargo build -p fluidbox-server"
}

# ── up ───────────────────────────────────────────────────────────────────
demo_up() {
  local t0=$SECONDS
  trap 'echo; warn "interrupted — cleaning up"; demo_down; exit 130' INT TERM
  preflight

  say "starting the demo stack (isolated: project fluidbox-demo, port $PORT, db $DB_PORT)"
  SERVER_BIN=""; resolve_server_bin
  mkdir -p "$DEMO_DIR/data"
  FLUIDBOX_DEMO_DB_PORT="$DB_PORT" "${COMPOSE[@]}" up -d --wait --quiet-pull postgres \
    || die "demo Postgres failed to start" "Inspect: docker compose -p fluidbox-demo -f deploy/docker-compose.demo.yml logs postgres"
  ok "demo Postgres healthy on 127.0.0.1:$DB_PORT (volume fluidbox-demo-pgdata)"

  if ! docker image inspect "$REPLAY_IMAGE" >/dev/null 2>&1; then
    warn "building the replay runner image ($REPLAY_IMAGE)"
    docker build -t "$REPLAY_IMAGE" -f "$ROOT/images/replay-runner/Dockerfile" "$ROOT/images" >/dev/null \
      || die "replay image build failed" "Re-run with: docker build -t $REPLAY_IMAGE -f images/replay-runner/Dockerfile images"
  fi
  ok "replay runner image ready ($REPLAY_IMAGE)"

  local ADMIN_TOKEN; ADMIN_TOKEN=$(openssl rand -hex 32 2>/dev/null || python3 -c "import secrets;print(secrets.token_hex(32))")
  ( umask 077; echo "$ADMIN_TOKEN" > "$DEMO_DIR/admin-token" )

  # Launch the control plane with a fully explicit environment: `just` loads
  # .env into recipes, so everything load-bearing is overridden here and the
  # multi-user/KMS/RLS knobs are cleared for the single-admin demo posture.
  env -u FLUIDBOX_REQUIRE_SSO -u FLUIDBOX_RUNTIME_ROLE -u FLUIDBOX_KMS_MODE \
      -u FLUIDBOX_LLM_KEY_MODE -u FLUIDBOX_METRICS_BIND -u FLUIDBOX_ALLOW_RLS_BYPASS \
      -u FLUIDBOX_CREDENTIAL_KEY -u ANTHROPIC_API_KEY -u FLUIDBOX_GITHUB_API_URL \
      -u FLUIDBOX_EGRESS_PROXY \
    DATABASE_URL="postgres://fluidbox:fluidbox@127.0.0.1:$DB_PORT/fluidbox" \
    FLUIDBOX_ADMIN_TOKEN="$ADMIN_TOKEN" \
    FLUIDBOX_BIND="0.0.0.0:$PORT" \
    FLUIDBOX_INTERNAL_BIND="127.0.0.1:$INTERNAL_PORT" \
    FLUIDBOX_PUBLIC_CONTROL_URL="http://host.docker.internal:$PORT" \
    FLUIDBOX_DATA_DIR="$DEMO_DIR/data" \
    FLUIDBOX_SANDBOX_IMAGE="$REPLAY_IMAGE" \
    LITELLM_MASTER_KEY="demo-unused-no-model-calls" \
    LLM_UPSTREAM_URL="http://127.0.0.1:9" \
    RUST_LOG="${RUST_LOG:-info}" \
    "$SERVER_BIN" >> "$DEMO_DIR/server.log" 2>&1 &
  echo $! > "$DEMO_DIR/server.pid"
  disown

  local healthy=""
  for _ in $(seq 1 120); do
    curl -fsS -m 2 "$API/v1/health" >/dev/null 2>&1 && { healthy=1; break; }
    kill -0 "$(cat "$DEMO_DIR/server.pid")" 2>/dev/null || break
    sleep 0.5
  done
  if [ -z "$healthy" ]; then
    printf "%s" "$RED"; echo "  ✗ control plane did not become healthy in 60s. Last log lines:"; printf "%s" "$RESET"
    tail -20 "$DEMO_DIR/server.log" | sed 's/^/    /'
    echo "    full log: $DEMO_DIR/server.log"
    echo "    likely causes: demo db port unreachable, or a migration failure (see above)"
    demo_down
    exit 2
  fi
  ok "control plane healthy on $API (migrations applied on boot)"

  say "seeding the demo (policy + agent + sample repo)"
  local H="authorization: Bearer $ADMIN_TOKEN"
  python3 - "$ROOT/scripts/demo-policy.yaml" > "$DEMO_DIR/policy-body.json" <<'PYEOF'
import json, sys
print(json.dumps({"name": "demo", "yaml": open(sys.argv[1]).read()}))
PYEOF
  curl -fsS -X POST -H "$H" -H 'content-type: application/json' \
      -d @"$DEMO_DIR/policy-body.json" "$API/v1/policies" >/dev/null \
    || die "failed to import the demo policy" "server log: $DEMO_DIR/server.log" "the demo stack was left up for inspection — remove it with: just demo-down"
  ok "policy 'demo' imported (allow tests/edits · deny curl/wget · approval for deploy)"
  curl -fsS -X POST -H "$H" -H 'content-type: application/json' -d "$(python3 - "$REPLAY_IMAGE" <<'PYEOF'
import json, sys
print(json.dumps({
  "name": "demo-fixer",
  "description": "five-minute demo agent (deterministic replay; no model calls)",
  "harness": "claude-agent-sdk",
  "model": "claude-haiku-4-5",
  "system_prompt": "Deterministic replay of a recorded run. No model is consulted.",
  "policy": "demo",
  "runner_image": sys.argv[1],
}))
PYEOF
)" "$API/v1/agents" >/dev/null || die "failed to create the demo agent" "server log: $DEMO_DIR/server.log" "the demo stack was left up for inspection — remove it with: just demo-down"
  ok "agent 'demo-fixer' created (runner_image=$REPLAY_IMAGE, policy=demo)"
  rm -rf "$DEMO_DIR/repo" && cp -R "$ROOT/scripts/demo-fixture" "$DEMO_DIR/repo"
  ok "sample repo staged at .demo/repo (fluidbox will run against a copy of the copy)"

  say "the run — watch the gate work; your approval is the only thing that releases the deploy"
  local SID
  SID=$(curl -fsS -X POST -H "$H" -H 'content-type: application/json' -d "$(python3 - "$DEMO_DIR/repo" <<'PYEOF'
import json, sys
print(json.dumps({
  "agent": "demo-fixer",
  "task": "Fix the failing test in demo-service, then deploy. [deterministic replay — no model calls]",
  "workspace": {"kind": "local_copy", "path": sys.argv[1]},
  "autonomous": False,
}))
PYEOF
)" "$API/v1/sessions" | python3 -c "import sys,json;print(json.load(sys.stdin)['session']['id'])") \
    || die "failed to create the run" "server log: $DEMO_DIR/server.log" "the demo stack was left up for inspection — remove it with: just demo-down"
  echo "$SID" > "$DEMO_DIR/session-id"
  ok "run created: $SID"

  FBX_API="$API" FBX_TOKEN="$ADMIN_TOKEN" FBX_SID="$SID" FBX_DEMO_DIR="$DEMO_DIR" \
  FBX_DECISION="${FLUIDBOX_DEMO_DECISION:-}" python3 -u - <<'PYEOF'
import json, os, select, signal, subprocess, sys, time, urllib.request

# Die BY the signal (not a normal exit-130): bash's cooperative-SIGINT rule
# ignores its own pending INT trap when the foreground child exits normally,
# which would leave the stack running after a Ctrl-C.
def _sigint(_sig, _frm):
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    os.kill(os.getpid(), signal.SIGINT)
signal.signal(signal.SIGINT, _sigint)
API, TOKEN, SID = os.environ["FBX_API"], os.environ["FBX_TOKEN"], os.environ["FBX_SID"]
DEMO_DIR, DECISION = os.environ["FBX_DEMO_DIR"], os.environ.get("FBX_DECISION") or None
BOLD, DIM, RED, GREEN, YELLOW, CYAN, R = "\033[1m", "\033[2m", "\033[1;31m", "\033[1;32m", "\033[1;33m", "\033[1;36m", "\033[0m"

def api(path, body=None):
    req = urllib.request.Request(API + path, headers={"authorization": "Bearer " + TOKEN})
    if body is not None:
        req.data = json.dumps(body).encode()
        req.add_header("content-type", "application/json")
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read() or b"{}")

def snapshot_sandbox():
    try:
        ids = subprocess.run(["docker", "ps", "-q", "--filter", f"label=fluidbox.session={SID}"],
                             capture_output=True, text=True, timeout=10).stdout.split()
        if not ids:
            return
        raw = subprocess.run(["docker", "inspect", ids[0]], capture_output=True, text=True, timeout=10).stdout
        with open(os.path.join(DEMO_DIR, "sandbox-inspect.json"), "w") as f:
            f.write(raw)
    except Exception as e:
        print(f"  {DIM}(could not snapshot sandbox container: {e}){R}")

def decide(aid, tool, summary, expires_at):
    print(f"\n  {YELLOW}{BOLD}⏸  APPROVAL REQUIRED{R}  {tool}: {summary}")
    print(f"  {DIM}policy 'demo' sends unlisted commands to a human; auto-deny at {expires_at}{R}")
    snapshot_sandbox()
    choice = None
    if DECISION == "wait":
        print(f"  {DIM}(FLUIDBOX_DEMO_DECISION=wait — leaving it to the policy TTL auto-deny){R}")
        return
    if DECISION in ("approve", "deny"):
        time.sleep(2)
        choice = DECISION
        print(f"  {DIM}(FLUIDBOX_DEMO_DECISION={DECISION}){R}")
    elif sys.stdin.isatty():
        print(f"  {BOLD}[a]pprove once / [d]eny{R} → ", end="", flush=True)
        ready, _, _ = select.select([sys.stdin], [], [], 170)
        ans = sys.stdin.readline().strip().lower() if ready else ""
        choice = "approve" if ans.startswith("a") else ("deny" if ans.startswith("d") else None)
        if choice is None:
            print(f"  {DIM}no answer — letting the 3-minute TTL auto-deny{R}")
    else:
        time.sleep(2)
        choice = "approve"
        print(f"  {DIM}(no TTY — auto-approving; set FLUIDBOX_DEMO_DECISION=deny for the other path){R}")
    if choice:
        decision = "approved_once" if choice == "approve" else "denied"
        api(f"/v1/approvals/{aid}/decision", {"decision": decision})
        verb = "approved" if choice == "approve" else "denied"
        print(f"  {GREEN if choice=='approve' else RED}→ you {verb} it{R} (recorded in the audit ledger)")

ICON = {"allow": f"{GREEN}✓ allow{R}", "deny": f"{RED}✗ deny{R}", "require_approval": f"{YELLOW}⏸ approval{R}"}
seq, status = 0, None
while True:
    try:
        evs = api(f"/v1/sessions/{SID}/events?after={seq}&limit=200").get("events", [])
    except Exception:
        time.sleep(0.5)
        continue
    for e in evs:
        seq = e["seq"]
        kind, d = e["payload"]["type"], e["payload"]["data"]
        if kind == "session.status_changed":
            print(f"  {DIM}[{seq:>3}]{R} {CYAN}state{R} {d.get('from')} → {BOLD}{d.get('to')}{R}")
            if d.get("to") in ("completed", "failed", "cancelled", "budget_exceeded"):
                status = d.get("to")
        elif kind == "workspace.initialized":
            print(f"  {DIM}[{seq:>3}]{R} workspace ready: {d.get('files')} files, base {str(d.get('base_commit'))[:10]}")
        elif kind == "agent.message":
            text = (d.get("text") or "").strip()
            pad = "\n        "
            print(f"  {DIM}[{seq:>3}]{R} {BOLD}agent{R} │ " + pad.join(text.splitlines()[:12]))
        elif kind == "tool.requested":
            print(f"  {DIM}[{seq:>3}]{R} tool.requested  {BOLD}{d.get('tool')}{R} {DIM}{(d.get('summary') or '')[:90]}{R}")
        elif kind == "tool.decision":
            v = d.get("verdict"); s = d.get("source")
            print(f"  {DIM}[{seq:>3}]{R} tool.decision   {ICON.get(v, v)} {DIM}(source={s}{', '+d.get('reason') if d.get('reason') else ''}){R}")
        elif kind == "approval.requested":
            decide(d.get("approval_id"), d.get("tool"), d.get("summary"), d.get("expires_at"))
        elif kind == "approval.decided":
            print(f"  {DIM}[{seq:>3}]{R} approval.decided → {BOLD}{d.get('decision')}{R} by {d.get('decided_by')}")
        elif kind == "run.result":
            print(f"  {DIM}[{seq:>3}]{R} {BOLD}result{R}: {d.get('outcome')} — {d.get('summary')}")
        elif kind == "artifact.collected":
            print(f"  {DIM}[{seq:>3}]{R} artifact: {d.get('kind')} ({d.get('bytes')} bytes, sha256 {str(d.get('sha256'))[:12]}…)")
        elif kind in ("session.created", "capability.frozen"):
            print(f"  {DIM}[{seq:>3}] {kind}{R}")
        else:
            print(f"  {DIM}[{seq:>3}] {kind}{R}")
    if status:
        # Hand the STATUS STRING back to bash, not just an exit code: the
        # failure banner has to name what happened, and "failed" vs "cancelled"
        # vs "budget_exceeded" are different stories to tell.
        with open(os.path.join(DEMO_DIR, "run-status"), "w") as f:
            f.write(status)
        sys.exit(0 if status == "completed" else 3)
    time.sleep(0.3)
PYEOF
  local RUN_STATUS=$?
  if [ $RUN_STATUS -ge 128 ]; then
    # Signal-terminated watcher = the user interrupted. Belt-and-braces with
    # the INT trap (bash versions differ on trap delivery here).
    echo; warn "interrupted — cleaning up"; demo_down; exit 130
  fi
  # 3 is the watcher's DELIBERATE "the run reached a non-completed terminal
  # state". Anything else non-zero is the watcher itself breaking.
  #
  # This used to read `[ $RUN_STATUS -le 3 ] || die …`, which accepted 3 as
  # success — so a run that FAILED printed the whole success-shaped receipt,
  # including "every tool call crossed the server-side gate: 0 decisions" (a
  # sentence that refutes itself), followed by a cheerful next-steps block, and
  # exited 0. It also swallowed 1 and 2, i.e. an unhandled exception in the
  # watcher. A demo that cannot fail is not evidence of anything.
  local RUN_OUTCOME=""
  if [ $RUN_STATUS -eq 3 ]; then
    RUN_OUTCOME=$(cat "$DEMO_DIR/run-status" 2>/dev/null || echo "not completed")
  elif [ $RUN_STATUS -ne 0 ]; then
    die "timeline watcher failed (exit $RUN_STATUS)" \
        "This is the watcher breaking, not the run failing — see the trace above." \
        "the demo stack was left up for inspection — remove it with: just demo-down"
  fi

  if [ -n "$RUN_OUTCOME" ]; then
    printf "\n%s  ✗ THE RUN DID NOT COMPLETE — terminal state: %s%s\n" "$RED" "$RUN_OUTCOME" "$RESET"
    printf "    The receipts below are still printed because they are the best\n"
    printf "    diagnostic available, but this is a FAILED demo, not a successful one.\n"
    printf "    Server log: %s\n" "$DEMO_DIR/server.log"
    printf "    Most common cause: the control plane could not reach the daemon holding\n"
    printf "    %s — see 'docker endpoint' in the preflight output above.\n" "$REPLAY_IMAGE"
  fi

  say "receipts — everything below is read back from the control plane, not asserted by this script"
  curl -m 15 -fsS -H "$H" "$API/v1/sessions/$SID/events?limit=500" > "$DEMO_DIR/receipt-events.json"
  curl -m 15 -fsS -H "$H" "$API/v1/sessions/$SID/cost" > "$DEMO_DIR/receipt-cost.json"
  curl -m 15 -fsS -H "$H" "$API/v1/sessions/$SID/artifacts" > "$DEMO_DIR/receipt-artifacts.json"
  curl -m 15 -fsS -H "$H" "$API/v1/sessions/$SID/approvals" > "$DEMO_DIR/receipt-approvals.json"
  curl -m 15 -fsS -H "$H" "$API/v1/sessions/$SID" > "$DEMO_DIR/receipt-session.json"
  FBX_DEMO_DIR="$DEMO_DIR" FBX_API="$API" FBX_TOKEN="$ADMIN_TOKEN" FBX_SID="$SID" python3 -u - <<'PYEOF'
import json, os, urllib.request
D = os.environ["FBX_DEMO_DIR"]; API=os.environ["FBX_API"]; TOKEN=os.environ["FBX_TOKEN"]; SID=os.environ["FBX_SID"]
BOLD, DIM, GREEN, YELLOW, CYAN, R = "\033[1m", "\033[2m", "\033[1;32m", "\033[1;33m", "\033[1;36m", "\033[0m"
evs = json.load(open(f"{D}/receipt-events.json"))["events"]
cost = json.load(open(f"{D}/receipt-cost.json"))
arts = json.load(open(f"{D}/receipt-artifacts.json"))
apps = json.load(open(f"{D}/receipt-approvals.json"))

print(f"\n{BOLD}── the diff (what actually changed in the workspace) ─────────────{R}")
diff_art = next((a for a in arts.get("artifacts", []) if a.get("kind") == "diff"), None)
if diff_art:
    req = urllib.request.Request(f"{API}/v1/sessions/{SID}/artifacts/{diff_art['id']}",
                                 headers={"authorization": "Bearer " + TOKEN})
    content = json.loads(urllib.request.urlopen(req, timeout=30).read())["artifact"].get("content", "")
    open(f"{D}/receipt-diff.patch", "w").write(content)
    lines = content.splitlines()
    for l in lines[:60]:
        c = GREEN if l.startswith("+") and not l.startswith("+++") else ("\033[31m" if l.startswith("-") and not l.startswith("---") else DIM)
        print(f"  {c}{l}{R}")
    if len(lines) > 60:
        print(f"  {DIM}… {len(lines)-60} more lines — full patch: .demo/receipt-diff.patch{R}")
else:
    print(f"  {DIM}(no diff artifact){R}")

u = cost.get("usage", {})
print(f"\n{BOLD}── the bill ──────────────────────────────────────────────────────{R}")
print(f"  model spend: {GREEN}${u.get('cost_usd', 0):.2f}{R} · {u.get('requests', 0)} model requests · {cost.get('tool_calls', 0)} tool calls")
print(f"  {DIM}$0.00 is a property of replay mode — a live run meters real usage here{R}")

print(f"\n{BOLD}── the security receipt ──────────────────────────────────────────{R}")
dec = [e["payload"]["data"] for e in evs if e["payload"]["type"] == "tool.decision"]
from collections import Counter
tally = Counter((d.get("verdict"), d.get("source")) for d in dec)
# Say what was MEASURED, and say it differently when nothing was. The old
# wording asserted the guarantee ("every tool call crossed the server-side
# gate") and then printed the count next to it — which on a failed run rendered
# "every tool call crossed the server-side gate: 0 decisions", a security
# receipt that refutes itself. The count is the evidence; the guarantee is not
# something this script is in a position to assert.
if dec:
    print(f"  {len(dec)} tool calls were decided server-side, before execution:")
else:
    print(f"  {YELLOW}⚠ ZERO gate decisions were recorded.{R}")
    print(f"    Nothing reached the gate, so this run demonstrates NO governance.")
    print(f"    On a run that ended before the agent started this is expected;")
    print(f"    on a run that changed files it would be a serious defect.")
for (v, s), n in sorted(tally.items()):
    print(f"    {v:<18} ×{n}  {DIM}(source={s}){R}")
for a in apps.get("approvals", []):
    print(f"  approval {a['id'][:8]}… {a['tool']} «{a['summary']}» → {BOLD}{a['status']}{R} by {a.get('decided_by')}")
insp_path = f"{D}/sandbox-inspect.json"
if os.path.exists(insp_path):
    i = json.load(open(insp_path))[0]
    hc, cfg = i.get("HostConfig", {}), i.get("Config", {})
    print(f"  sandbox container (captured live at the approval pause):")
    print(f"    image={cfg.get('Image')}  user={cfg.get('User')}  network={hc.get('NetworkMode')}")
    print(f"    cap_drop={hc.get('CapDrop')}  pids_limit={hc.get('PidsLimit')}  memory={hc.get('Memory')//(1<<30) if hc.get('Memory') else '?'}GiB")
    print(f"    {DIM}fresh container per run; full JSON: .demo/sandbox-inspect.json{R}")
first_msg = next((e for e in evs if e["payload"]["type"] == "agent.message"), None)
if first_msg:
    print(f"  {DIM}ledger stores digests + verdicts, never raw model prompts; RunSpec froze the policy at create{R}")
print(f"  {DIM}full evidence: .demo/receipt-*.json (events, cost, artifacts, approvals, session){R}")
PYEOF

  # A failed run has no "next steps" — offering the graduation path after a
  # failure is what made the old output read as success.
  if [ -n "$RUN_OUTCOME" ]; then
    say "what to do about the failure"
    cat <<EOF
  1. Check the docker endpoint the CONTROL PLANE used (printed in preflight).
     The demo's own preflight and the server must agree; if they do not, the
     preflight passes against one daemon and the run fails against another.
  2. Read the tail of $DEMO_DIR/server.log — a provisioning failure names the
     image it could not find.
  3. just demo-down, then re-run.
EOF
    printf "\n  %stotal: %ss%s\n" "$DIM" "$((SECONDS - t0))" "$RESET"
    trap - INT TERM
    if [ -n "${FLUIDBOX_DEMO_KEEP:-}" ]; then
      warn "FLUIDBOX_DEMO_KEEP set — leaving the stack up for inspection (API $API)"
    else
      demo_down
    fi
    die "demo run did not complete (terminal state: $RUN_OUTCOME)"
  fi

  say "next steps"
  local have_key=""
  [ -n "${ANTHROPIC_API_KEY:-}" ] && have_key=1
  [ -z "$have_key" ] && [ -f "$ROOT/.env" ] && grep -q '^ANTHROPIC_API_KEY=..' "$ROOT/.env" && have_key=1
  if [ -n "$have_key" ]; then
    cat <<EOF
  You already have an ANTHROPIC_API_KEY configured. To run a LIVE agent (a real
  model, same governance):
    1. just demo-down                 # clear the demo stack
    2. just dev                       # gateway + control plane + dashboard
    3. cargo run -p fluidbox-cli -- run --task "fix the failing test" --repo scripts/demo-fixture
  The dashboard (http://localhost:3000) shows the same timeline you just watched.
EOF
  else
    cat <<EOF
  To graduate to a LIVE agent (a real model, same governance):
    1. add ANTHROPIC_API_KEY=sk-ant-… to .env   (only the LiteLLM container ever sees it)
    2. just demo-down && just dev
    3. cargo run -p fluidbox-cli -- run --task "fix the failing test" --repo scripts/demo-fixture
EOF
  fi

  printf "\n  %stotal: %ss%s\n" "$DIM" "$((SECONDS - t0))" "$RESET"
  trap - INT TERM
  if [ -n "${FLUIDBOX_DEMO_KEEP:-}" ]; then
    warn "FLUIDBOX_DEMO_KEEP set — leaving the stack up (API $API, token in .demo/admin-token)"
    warn "tear down later with: just demo-down"
  elif [ -t 0 ]; then
    printf "  tear the demo down now? [Y/n] "
    read -r ans || ans=""
    case "$ans" in n|N|no) warn "leaving the stack up — \`just demo-down\` when you're done";;
                   *) demo_down;; esac
  else
    demo_down
  fi
}

case "${1:-up}" in
  up) demo_up ;;
  down) demo_down ;;
  purge) demo_purge ;;
  *) die "unknown subcommand: $1 (use: up | down | purge)" ;;
esac
