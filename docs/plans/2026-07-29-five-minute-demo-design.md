# Five-minute first-run demo (`just demo`) + launch media — design

Status: design settled; build tracked in `docs/plans/2026-07-29-five-minute-demo-plan.md`.
Author: Claude (autonomous goal session, 2026-07-29). Decisions below were made against the
/goal directive of 2026-07-29; rationale is recorded per decision so any can be revisited.

## 1. Goal

A single command — `just demo` — that takes a fresh clone (or a running dev machine) to a
complete, governed fluidbox run in about five minutes, **without an Anthropic key**, then
tells the user exactly how to graduate to a live agent. The verified workflow then becomes
the factual backbone for launch media (five Remotion deliverables in the existing
`fluidbox-demo-film` visual language).

Non-goals: dashboards (`pnpm` install is minutes we don't have — the terminal is the UI;
the dashboard is a next-step pointer), Kubernetes (docker provider only), live model calls
(that is the *next step*, not the demo), multi-user/SSO (single-admin posture), Windows.

## 2. The honest core: a deterministic replay through the real gate

The demo runs a **real session end to end** — real control plane, real Postgres, real
sandbox container, real policy engine, real approval row, real diff artifact — with one
substitution: the harness inside the sandbox is a **replay driver**, not a model. It
replays a canned transcript of tool calls through the exact runner contract
(`/permission` per call, `/events`, `/heartbeat`, `/result`), and **actually executes**
each allowed step against `/workspace` (real file edit, real test run). Every governance
artifact the demo shows is therefore produced by the same code paths a live run uses.

Honesty rules (non-negotiable, enforced in copy and code):
- The banner, the session task text, and the first timeline message all say
  **"deterministic replay — no model calls"**. Nothing may present the replay as a live
  model run.
- The cost receipt prints the true numbers: `$0.00, 0 model requests` (from
  `GET /v1/sessions/{id}/cost`), labelled as a property of replay mode.
- No invented security behavior: every security line in the receipt is read from a real
  source at demo time (`docker inspect` for container posture, the event ledger for gate
  decisions, the policy YAML for rules). Local docker sandboxes are NOT claimed to be
  zero-egress (that is the k8s provider's netpol story); the demo's network beat is
  *policy*-level (a `curl` step denied by rule).

Why not the real Claude-SDK harness against a fake LLM upstream: (a) it would
demonstrate an SDK conversation that never happened — exactly the "replay presented as a
live run" failure the goal forbids; (b) the SDK harness currently has an open
gate-bypass bug (live tool calls skipping `canUseTool`; tracked in memory, not yet
fixed), so the one thing the demo must show is the thing that path cannot show today.
The replay driver speaks the runner contract directly, so the server-side gate — which
is sound — is what the audience sees. Why not the codex fake-app-server trick from
`scripts/e2e-codex-replay.sh`: it proves supervisor canonicalization, but it performs no
real file edits, produces no diff, and drags a 1.4 GB image + NDJSON protocol emulation
into a first-run path. A purpose-built ~small replay image is simpler and legible.

## 3. Components

### 3.1 `images/replay-runner/` — the third runner image
- `FROM node:24-bookworm-slim` + `git` (the workspace is a git repo; fixture scripts use
  bash, present in bookworm). Shares `images/runner-lib` exactly like the other two
  images (`COPY runner-lib ./lib`), same `entrypoint.sh` token-handoff pattern, same
  non-root uid 10001, same env contract (`loadRunnerEnv`).
- `runner/index.mjs`: reads the transcript baked at `/opt/fluidbox-replay/transcript.json`,
  then for each step: `agent.message` narration via `emit()`, or a tool step →
  `requestPermission(tool, input, id)` → on `allow` **execute for real** (Bash via
  `child_process` in `/workspace` with a step timeout; Edit/Write via string-replace /
  file write with the canonical `{file_path, old_string, new_string}` shapes) → emit a
  short `agent.message` with the outcome (the server's ledger already carries
  `tool.requested`/`tool.decision`; runner-posted `tool.requested` is dropped by design).
  On `deny` → narrate and continue (every step is deny-tolerant; the transcript is
  written so denial of any step still reaches a coherent result). Heartbeats +
  token-renew via `RunnerClient` as-is. Ends with `postResult("completed", summary)`.
- Determinism: no model, no network (the driver itself talks only to the control plane),
  fixed transcript, fixed fixture. Two consecutive runs differ only in ids/timestamps.
- Registered nowhere server-side: the demo agent pins `runner_image` explicitly
  (`POST /v1/agents` accepts it), harness stays `claude-agent-sdk` (facade dialect is
  irrelevant — the driver never calls the LLM facade). No Rust changes.

### 3.2 Demo fixture repo (`scripts/demo-fixture/`, copied per run)
A ~5-file toy service: `app.js` (a `greet()` with a real bug), `test.js`,
`run_tests.sh` (`node test.js`), `deploy.sh` (append a release line to `deploy.log` —
the "dangerous" action the gate protects), `README.md`. The demo copies it to
`$DEMO_DIR/repo` and creates the session with `workspace={kind:"local_copy", path}` —
the orchestrator copies it again into the session workspace, git-inits, and diffs
against that baseline at finalize, so the fixture itself is never mutated.

### 3.3 Demo policy (YAML via `POST /v1/policies`, name `demo`)
```yaml
defaults: { tool_action: approve }
approvals: { default_ttl_secs: 180, timeout_action: deny }
tools:
  - match: [Read, Glob, Grep, LS]
    action: allow
  - match: [Edit, Write, MultiEdit]
    action: allow
    paths: { allow: ["/workspace/**"], deny: ["**/.env", "**/secrets*"] }
  - match: [Bash]
    action: allow
    shell:
      allow_prefixes: ["./run_tests.sh", "ls", "cat ", "git status", "git diff"]
      deny_regex: ["\\bcurl\\b", "\\bwget\\b", "rm\\s+-rf"]
      on_no_match: approve
```
Three visible verdict classes from one small policy: allow (tests, edit), **hard deny**
(the transcript's `curl https://status.demo.internal/health` step — narrated as "network
calls are denied by policy here"), **require_approval** (`./deploy.sh`, not in
allow_prefixes → `on_no_match: approve`, 3-minute TTL so an abandoned prompt auto-denies
and the run still completes).

### 3.4 Transcript (baked into the image)
intro message → `Bash ./run_tests.sh` (fails, output shown) → diagnosis message →
`Edit app.js` (the fix) → `Bash ./run_tests.sh` (passes) → `Bash curl …` (**policy
deny**) → `Bash ./deploy.sh` (**approval pause** — the human moment) → wrap-up message →
result. Denied deploy is a first-class ending ("deploy withheld by operator"), not a
failure.

### 3.5 `scripts/demo.sh` (+ `just demo`, `just demo-down`)
Phases, each timed and printed:
1. **Preflight** — `docker info` (actionable error if the daemon is down, naming
   Docker Desktop/colima), `cargo`, `python3`, `curl` present; ports free (demo defaults
   below); disk-space sanity for the image build. Prints "no API key required" up front.
2. **Stale-state sweep** — a previous demo (pidfile, compose project `fluidbox-demo`,
   demo containers by label) is torn down first; `just demo` is therefore idempotent and
   double-invocation-safe.
3. **Start** — compose project `fluidbox-demo` (its own file
   `deploy/docker-compose.demo.yml`): `postgres:17-alpine` on `127.0.0.1:5434`, volume
   `fluidbox-demo-pgdata`. `cargo build` (first run compiles; say so honestly with a
   progress note) then run `fluidbox-server` bound to the demo ports with a
   generated-per-run admin token, `FLUIDBOX_DATA_DIR=$DEMO_DIR/data`,
   `LITELLM_MASTER_KEY=demo-unused` (boot requires non-empty; replay never calls it),
   logs to `$DEMO_DIR/server.log`. Health-wait on `/v1/health` with a bounded timeout →
   on timeout, print the last 20 log lines + the log path.
4. **Seed** — policy `demo` + agent `demo-fixer` (pins the replay image; built here via
   `docker build` if missing, ~seconds) + fixture copy.
5. **Run** — `POST /v1/sessions`, then poll `GET …/events?after=seq` (~300 ms) and
   pretty-print the timeline (gate verdicts colored, digests shown). On
   `approval.requested`: show the tool + summary and prompt
   `Approve ./deploy.sh? [a]pprove / [d]eny (auto-deny in 3m)` → POST the decision.
6. **Receipts** — diff artifact (`kind=diff`), cost (`$0.00 / 0 requests`, labelled
   replay), and a security receipt assembled from real sources: gate decisions count by
   verdict/source from the ledger, the approval row (who/when), container posture from
   `docker inspect` (cap_drop ALL, pids 512, 2 GiB, non-root, per-session network,
   fresh-per-run), RunSpec frozen-at-create note, redaction note (prompts never stored —
   digests only).
7. **Next step** — if `ANTHROPIC_API_KEY` is present in the environment or `.env`:
   print the exact live-run commands (`just dev`, `cargo run -p fluidbox-cli -- run …`).
   If not: where to put the key. Also: dashboard pointer, docs pointer.
8. **Teardown** — `just demo-down` (also offered at the end, and run automatically on
   Ctrl-C via trap): kill server (pidfile), `docker compose -p fluidbox-demo down -v`
   (volume removed — demo data is disposable by contract), remove `$DEMO_DIR`,
   keep the replay image (it is the only cached thing; `--purge` removes it too).

Isolation: demo never reads `.env` (self-contained env; only peeks at
`ANTHROPIC_API_KEY` for the next-step hint), never touches `fluidbox-pgdata`, dev ports
(8787/8788/5433/4000/3000), or the user's data dir. Demo ports: server **8790** (public)
/ **8791** (internal bind, set explicitly), Postgres **5434**; overridable via
`FLUIDBOX_DEMO_PORT` / `FLUIDBOX_DEMO_DB_PORT`. `$DEMO_DIR` = `.demo/` in the repo
(gitignored).

## 4. Mandated failure matrix

| Scenario | Behavior |
|---|---|
| Docker daemon down/absent | Preflight fails fast: "Docker is not running. Start Docker Desktop (or `colima start`), then re-run `just demo`." |
| Port collision | Preflight names the port, the listening process (`lsof`), and the override env var; exits before any state is created. |
| Repeated invocation | Stale-sweep first — always converges to one fresh demo; a second concurrent invocation is refused via pidfile+liveness check. |
| Interruption (Ctrl-C) | `trap INT/TERM` runs full teardown; message: nothing left running, re-run any time. |
| Health timeout | Bounded wait; on expiry: last server log lines, log path, and the two most likely causes (port bound but unhealthy DB; migration failure). Teardown offered. |
| Missing API keys | Not an error: demo states up front that replay needs none; live next-step branches on key presence with exact instructions. |

## 5. Validation plan (evidence feeds the media claim table)

On this machine, with the user's dev stack left running untouched: approve path,
deny path, approval-timeout path, Ctrl-C mid-run, double invocation, port-collision
drill (occupy 8790), docker-down drill (DOCKER_HOST pointed at a dead socket), health
timeout drill (unreachable DB port), and `just demo-down` leaving zero
containers/volumes/processes/dirs. Each drill's transcript is captured under
`docs/reviews/2026-07-29-demo-validation/` together with the raw events JSON, artifact
list, cost JSON, and `docker inspect` extract of the sandbox — these files are the
citation targets for the film's claim-validation table.

## 6. Launch media (in `~/Documents/fluidbox-demo-film`, new branch `demo-clips`)

Reuses the film's design system verbatim (tokens/fonts/motion/primitives + product &
infra components: `PolicyGate`, `AuditLedger`, `DiffCard`, `RunTimeline`,
`RunSpecFreeze`, `CaptionTrack` with its `compact` props). All five deliverables are
**new additive compositions** in new files + new `<Composition>` registrations —
existing scenes, `Main`, timing data, and rendered outputs are untouched (and the
original film's G3/G4 "no finals until approved" hold is respected: no `Main` renders).

| ID | Spec | Content |
|---|---|---|
| `Hero45` | 1920×1080 · 30 fps · ~50 s · narrated | Problem → run lifecycle → gate pause (approval) → diff+receipts → close. |
| `Demo30` | 1920×1080 · ~30 s · narrated | The `just demo` terminal journey, faithfully recreated from the validated transcript (real command, real timeline lines, REPLAY badge visible). |
| `Gate15` | 1920×1080 · ~15 s · narrated | One beat: `./deploy.sh` hits the gate → approval → ledger rows. |
| `Vertical` | 1080×1920 · ~30 s · captions-first | Intentional 9:16 relayout (compact props, stacked panels), not a crop. |
| `SocialLoop` | 1920×1080 · ~8 s · **silent**, seamless loop | Gate verdict cycle (allow → deny → approve) with logo; loop-safe first/last frames. |

Narration: new restrained scripts (claims only from the validated demo + shipped,
evidenced behavior; wording avoids "zero-egress" for local docker, attributes k8s
claims to the k8s provider), ElevenLabs voice **River** `SAz9YHcvj6GT2YYXdXww`,
`eleven_multilingual_v2`, stability 0.55 / style 0.15 / speed 0.93 — the film's exact
recipe; aligned with the repo's whisper.cpp pipeline; per-clip timing/caption data
generated by the repo's existing scripts, extended per-composition (caption tests'
2×42-char rule kept). Music: reuse `audio/music/underscore.m4a` (ElevenLabs music API is
plan-gated — known 402). Deliverables ship with: storyboard doc, narration scripts,
captions, asset-provenance table, render commands, representative-frame inspection
notes, end-to-end watch log, and the claim-validation table (claim → clip timestamp →
evidence file/code ref). Renders go to `out/` (gitignored, per repo convention);
source + docs are committed on the branch (repo has no remote — local commits only).

## 7. Risks / accepted trade-offs

- First-ever `just demo` on a cold clone pays the Rust compile (minutes); we print it
  honestly rather than shipping binaries. Acceptable for a from-source OSS demo.
- `deploy.sh` is a fixture stand-in for a dangerous action; the gate, approval row,
  ledger, and conditional execution are the real subjects. The receipt says what
  `deploy.sh` actually did (append to `deploy.log`).
- The demo touches the shared docker daemon (image build + sandbox container) — labels +
  compose project scoping keep cleanup exact.
- The seeded `default` policy/agents in the demo DB are unused by the demo (it creates
  its own); no cross-contamination with the user's real DB is possible (separate
  cluster, separate volume).
