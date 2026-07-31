# Five-Minute Demo + Launch Media Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `just demo` — a localhost-only, no-key, deterministic first-run of a governed fluidbox run — then derive five Remotion launch clips from the validated workflow.

**Architecture:** A new `images/replay-runner/` image (runner-lib contract client + canned transcript, real execution of allowed steps) driven by `scripts/demo.sh` against an isolated demo stack (own compose project/ports/volume/data dir). Media work happens on a new branch in `~/Documents/fluidbox-demo-film`, additive compositions only.

**Tech Stack:** Bash + python3 (demo script, matching `scripts/e2e-lib.sh` idiom), Node 24 ESM (replay driver, `node:test`), Docker/compose, Remotion 4.0.498 + ElevenLabs MCP + whisper.cpp (media).

## Global Constraints

- No Rust changes anywhere in this plan; the server API already supports everything needed.
- Demo isolation: compose project `fluidbox-demo`, Postgres `127.0.0.1:15434` (volume `fluidbox-demo-pgdata`), server bind `0.0.0.0:19790`, internal bind `127.0.0.1:19791`, public control URL `http://host.docker.internal:19790`, data dir + workdir `.demo/` (gitignored). Never read `.env` except an optional peek at `ANTHROPIC_API_KEY` for the next-step hint.
- Honesty rules from the design doc §2 verbatim: replay is always labelled; costs printed truthfully ($0.00 / 0 requests); every security-receipt line reads from a live source (ledger / docker inspect / policy YAML); no zero-egress claims for local docker.
- Film repo: new branch `demo-clips`; only additive files + additive `Root.tsx` registrations; never render the original `Main`; renders stay in gitignored `out/`; narration = voice River `SAz9YHcvj6GT2YYXdXww`, `eleven_multilingual_v2`, stability 0.55 / style 0.15 / speed 0.93; captions obey the repo's 2-line × 42-char tests.
- The user's running dev stack (8787/8788/5433/4000/3000, volume `fluidbox-pgdata`) must never be touched by any step.

---

### Task 1: Replay driver + transcript (unit-tested, no docker)

**Files:**
- Create: `images/replay-runner/runner/index.mjs` (driver)
- Create: `images/replay-runner/runner/steps.mjs` (pure step executor)
- Create: `images/replay-runner/runner/transcript.json` (the canned scenario)
- Test: `images/replay-runner/runner/test/steps.test.mjs`, `.../test/driver.test.mjs`

**Interfaces:**
- Consumes: `/opt/fluidbox-runner/lib/contract.mjs` at runtime; in tests, `../steps.mjs` directly and a stub control-plane HTTP server.
- Produces: `executeStep(step, workspaceDir) -> {ok, output}` for `Bash{command}` / `Write{file_path,content}` / `Edit{file_path,old_string,new_string}`; transcript schema `[{say} | {tool, input, on_deny_say?}]`; driver env contract identical to the other runners (`FLUIDBOX_CONTROL_URL/SESSION_ID/TASK/WORKSPACE` + tokens via `loadRunnerEnv`).

- [ ] Step 1: Write failing `node:test` tests for `executeStep` (Bash runs in cwd with timeout + captured output; Write creates file; Edit fails on non-unique/missing `old_string`, applies on unique match; all paths confined to the workspace dir — reject `..`/absolute-outside paths).
- [ ] Step 2: `node --test images/replay-runner/runner/test/` → FAIL (module missing).
- [ ] Step 3: Implement `steps.mjs`; tests pass.
- [ ] Step 4: Write failing driver test: stub HTTP server implementing `/internal/sessions/{id}/permission|events|heartbeat|result|token/renew`; scripted verdicts (allow, allow, deny, allow); assert the driver (a) requests permission per tool step with stable `tool_call_id`s (`rp_001…`), (b) executes only allowed steps against a temp workspace, (c) narrates a deny via `on_deny_say` and continues, (d) posts exactly one `/result` `{outcome:"completed"}` whose summary reflects executed/denied counts, (e) sends `agent.message` events for `say` steps.
- [ ] Step 5: Implement `index.mjs` using `RunnerClient` (`emit`, `requestPermission`, `startHeartbeat`, `startTokenRenew`, `postResult`); transcript loaded from `REPLAY_TRANSCRIPT` env path defaulting to `/opt/fluidbox-replay/transcript.json`; first emitted message states the deterministic-replay fact. Driver imports contract via `RUNNER_LIB` env (defaults to the baked path) so tests can point it at `images/runner-lib`.
- [ ] Step 6: Author `transcript.json` = design §3.4 scenario (intro say → `Bash ./run_tests.sh` fail → say → `Edit app.js` → `Bash ./run_tests.sh` pass → say → `Bash curl https://status.demo.internal/health` with `on_deny_say` → `Bash ./deploy.sh` with `on_deny_say` → wrap say). Edit strings must match Task 3's fixture byte-for-byte.
- [ ] Step 7: All tests green; commit `feat(replay-runner): deterministic replay driver + transcript`.

### Task 2: Replay image + build recipe

**Files:**
- Create: `images/replay-runner/Dockerfile`, `images/replay-runner/entrypoint.sh` (copy sandbox-runner's token-handoff pattern)
- Modify: `justfile` (add `replay-build`)

**Interfaces:**
- Produces: image `fluidbox-replay-runner:dev` (overridable `FLUIDBOX_REPLAY_IMAGE`), `/opt/fluidbox-replay/{index.mjs,steps.mjs,transcript.json}`, lib at `/opt/fluidbox-runner/lib` (so the baked default import path matches sandbox-runner's), non-root uid 10001, ENTRYPOINT `entrypoint.sh node index.mjs`.

- [ ] Step 1: Dockerfile `FROM node:24-bookworm-slim`, `apt-get install -y --no-install-recommends git ca-certificates`, COPY `runner-lib` → `/opt/fluidbox-runner/lib`, COPY `replay-runner/runner` → `/opt/fluidbox-replay`, useradd 10001, WORKDIR /workspace.
- [ ] Step 2: `just replay-build` = `docker build -t ${FLUIDBOX_REPLAY_IMAGE:-fluidbox-replay-runner:dev} -f images/replay-runner/Dockerfile images` (context `images/`, same as siblings). Build it.
- [ ] Step 3: Smoke: `docker run --rm fluidbox-replay-runner:dev node -e "import('/opt/fluidbox-replay/steps.mjs').then(()=>console.log('ok'))"` prints ok. Commit `feat(replay-runner): image + just replay-build`.

### Task 3: Demo fixture + compose + gitignore

**Files:**
- Create: `scripts/demo-fixture/{app.js,test.js,run_tests.sh,deploy.sh,README.md}`
- Create: `deploy/docker-compose.demo.yml`
- Modify: `.gitignore` (add `.demo/`)

**Interfaces:**
- Produces: fixture where `./run_tests.sh` exits 1 before the Task 1 Edit and 0 after; `./deploy.sh` appends one line to `deploy.log` and prints it; compose project exposing Postgres 17-alpine on `127.0.0.1:${FLUIDBOX_DEMO_DB_PORT:-5434}` with volume `fluidbox-demo-pgdata` and healthcheck (mirrors `docker-compose.dev.yml`'s postgres service).

- [ ] Step 1: Fixture: `app.js` `greet(name)` returns `` `Hello, ${nam}!` `` (ReferenceError-free bug: use `"Hello, " + undefined` style — concretely `function greet(name){ return "Hello, nam!".replace("nam", nam); }` is over-cute; use the simple deterministic bug `return "Hello, " + namee + "!"` is a crash — pick: `return "Hello, name!"` literal, test expects `"Hello, Ada!"`; the Edit swaps `"Hello, name!"` → `` "Hello, " + name + "!" ``). `test.js` asserts `greet("Ada") === "Hello, Ada!"`, exits non-zero with a readable diff line. Scripts `chmod +x`, `#!/usr/bin/env bash`.
- [ ] Step 2: Verify: `cd scripts/demo-fixture && ./run_tests.sh` → exit 1 with the failure line; apply Task 1's exact Edit strings via `node -e` → `./run_tests.sh` → exit 0; `git checkout -- .` to restore the broken state.
- [ ] Step 3: Compose file; `docker compose -p fluidbox-demo -f deploy/docker-compose.demo.yml config -q` passes. Commit `feat(demo): fixture repo + demo compose`.

### Task 4: `scripts/demo.sh` up-path (preflight → healthy → seeded → run → receipts)

**Files:**
- Create: `scripts/demo.sh` (subcommands `up` default / `down` / `purge`)
- Create: `scripts/demo-policy.yaml` (design §3.3 verbatim)
- Modify: `justfile` (`demo`, `demo-down`)

**Interfaces:**
- Consumes: Task 2 image, Task 3 fixture/compose, `target/debug/fluidbox-server` (built here if absent).
- Produces: `.demo/{server.pid,server.log,admin-token,repo/,data/}`; exit codes: 0 success, 1 preflight, 2 startup/health, 3 run-phase failure.

- [ ] Step 1: Preflight fns (`need_docker` via `docker info`, `need_cmd cargo python3 curl git`, `port_free` on the demo ports (19790/19791/15434) via lsof with process naming + override-env hint) — each failure prints the exact fix and exits 1. Banner states "no API key required (deterministic replay)".
- [ ] Step 2: Stale sweep: if `.demo/server.pid` alive → this is a second invocation → refuse with "demo already running (pid N); run `just demo-down` first" unless the pid is dead → clean `.demo/`, `docker compose -p fluidbox-demo … down -v` best-effort, remove stray containers by label `fluidbox.session` + image ancestor filter scoped to the demo project only.
- [ ] Step 3: Start: compose up postgres `--wait`; `cargo build -p fluidbox-server` (message: first build compiles, later runs skip); launch server with the demo env block (design §3.5 phase 3: generated `FLUIDBOX_ADMIN_TOKEN` via `openssl rand -hex 32`, `DATABASE_URL=postgres://fluidbox:fluidbox@127.0.0.1:15434/fluidbox`, binds/URLs per Global Constraints, `LITELLM_MASTER_KEY=demo-unused`, `FLUIDBOX_DATA_DIR=$PWD/.demo/data`, `FLUIDBOX_SANDBOX_IMAGE=$REPLAY_IMAGE`); `wait_health` ≤120s on `:19790/v1/health` else print last 20 log lines + log path, teardown, exit 2.
- [ ] Step 4: Seed: build replay image if missing; `POST /v1/policies` with `scripts/demo-policy.yaml`; `POST /v1/agents` `{name:"demo-fixer", harness:"claude-agent-sdk", model:"claude-haiku-4-5", policy:{name:"demo"}, runner_image:$REPLAY_IMAGE, system_prompt:"(replay)"}`; copy fixture to `.demo/repo`.
- [ ] Step 5: Run: `POST /v1/sessions` `{agent:"demo-fixer", task:"Fix the failing test, then deploy. [deterministic replay — no model calls]", workspace:{kind:"local_copy",path:"$PWD/.demo/repo"}, autonomous:false}`; timeline loop: `GET /v1/sessions/$SID/events?after=$SEQ&limit=200` every 0.3s via python3 pretty-printer (event → one colored line; verdict + source shown; approval.requested triggers the interactive prompt `[a]pprove/[d]eny` → `POST /v1/approvals/$AID/decision {"decision":"approved_once"|"denied"}`; non-tty auto-approves after 2s with a printed note `FLUIDBOX_DEMO_DECISION=approve|deny` override for drills); loop ends on `session.status_changed.to ∈ {completed,failed,cancelled,budget_exceeded}`.
- [ ] Step 6: Receipts: diff artifact (list `/artifacts`, fetch `kind=diff`, print patch); cost `GET /cost` printed as `$0.00 · 0 model requests (replay mode)`; security receipt per design §3.5 phase 6 (ledger tallies via python3 over the events JSON; `docker inspect` of the session container by label for CapDrop/Pids/Memory/User/NetworkMode — capture BEFORE the orchestrator removes it, i.e. inspect at approval-pause time or accept absence with a printed note); next-step block (key-presence branch).
- [ ] Step 7: Live-verify the whole up-path on this machine (approve path). Fix until clean. Commit `feat(demo): just demo first-run experience`.

### Task 5: Teardown, traps, failure drills, evidence capture

**Files:**
- Modify: `scripts/demo.sh` (down/purge + `trap`)
- Create: `docs/reviews/2026-07-29-demo-validation/` (evidence: transcripts, events.json, artifacts.json, cost.json, inspect.json, drill logs)

**Interfaces:**
- Produces: `demo.sh down` = kill pid + compose down -v + rm -rf .demo (idempotent, safe when nothing exists); `purge` also `docker rmi` the replay image; `trap 'demo_down' INT TERM` during `up`.

- [ ] Step 1: Implement down/purge/trap; verify `just demo-down` from every state (never-run, healthy, mid-run) leaves zero: `docker ps -a` project-filtered empty, volume gone, no pid, no `.demo/`.
- [ ] Step 2: Drills, each captured to the evidence dir: (a) approve path (full transcript + all four JSON receipts), (b) deny path (`FLUIDBOX_DEMO_DECISION=deny`), (c) approval-timeout → auto-deny (policy ttl 180s — for the drill override the prompt to not answer; verify timeout source in ledger), (d) Ctrl-C mid-run → clean state, (e) double invocation → refusal message, (f) port collision (`python3 -m http.server on the demo port` occupying) → named process + override hint, (g) docker down (`DOCKER_HOST=unix:///nonexistent.sock`) → actionable message, (h) health timeout (`FLUIDBOX_DEMO_DB_PORT` pointed at a closed port) → log excerpt + exit 2.
- [ ] Step 3: Write `docs/reviews/2026-07-29-demo-validation/README.md` summarizing drill→result with file pointers. Commit `test(demo): validation drills + evidence`.

### Task 6: Repo docs + ship

**Files:**
- Modify: `README.md` ("Try it in five minutes" section), `CLAUDE.md` (commands table: `just demo` / `just demo-down`)

- [ ] Step 1: Docs edits (copy states no-key replay + what the demo shows + teardown promise).
- [ ] Step 2: `cargo fmt --check` (no Rust touched — expect clean), shellcheck `scripts/demo.sh` if available, `node --test` suite green, `docker compose … config -q`.
- [ ] Step 3: Commit; push branch; `gh pr create --draft` titled "feat(demo): five-minute no-key first-run (`just demo`) + replay runner"; body = design-doc summary + validation evidence pointers.

### Task 7: Film groundwork (sibling repo, non-destructive)

**Files (in `~/Documents/fluidbox-demo-film`):**
- Branch: `git switch -c demo-clips` (repo has no remote; local commits only)

- [ ] Step 1: Invoke `remotion:remotion-best-practices` + `remotion:remotion-render` (and `remotion:remotion-captions` before caption work); note any conflicts with repo conventions — repo wins.
- [ ] Step 2: Read `docs/superpowers/specs/2026-07-23-fluidbox-demo-film-design.md`, latest handover, `src/data/timing.ts` + `build-timing.mts`, `CaptionTrack`/`EndCard`/`RunTimeline`/`PolicyGate`/`AuditLedger`/`DiffCard`/`RunSpecFreeze` component APIs (props actually needed). `pnpm test && pnpm typecheck` green baseline.
- [ ] Step 3: Commit branch marker (empty change not needed — first real commit lands in Task 8).

### Task 8: Clip narration + per-clip timing data

**Files (film repo):**
- Create: `docs/clips/NARRATION.md` (four scripts + claim sources), `scripts/build-clip-timing.mts`, `src/data/clips/{hero45,demo30,gate15,vertical}.ts`, `audio/narration/clips/*.mp3` + alignments

**Interfaces:**
- Produces: per-clip `CLIP_TIMING` objects `{fps:30, totalFrames, phrases:[{text,startFrame,endFrame,emphasis[]}]}` consumed by Task 9 comps; caption chunks satisfying existing caption tests' shape.

- [ ] Step 1: Write the four scripts (hero ~110 words / demo30 ~70 / gate15 ~35 / vertical ~60), every factual clause mapped in a draft claim table to demo evidence (Task 5 dir), shipped code (`policy.rs` verdicts, `event.rs` kinds, docker provider limits), or the EKS acceptance docs (k8s-scoped wording only).
- [ ] Step 2: ElevenLabs TTS per script (River, film settings; one call per clip) → `audio/narration/clips/<id>.mp3`; whisper-align each (reuse repo's `whisper-align.mts` pattern); `build-clip-timing.mts` → `src/data/clips/<id>.ts`; clip caption tests added mirroring `tests/captions.test.ts` rules.
- [ ] Step 3: `pnpm test` green; commit `feat(clips): narration + timing data for launch clips`.

### Task 9: Five compositions

**Files (film repo):**
- Create: `src/clips/{ClipStage.tsx,Hero45.tsx,Demo30.tsx,Gate15.tsx,Vertical.tsx,SocialLoop.tsx}`
- Modify: `src/Root.tsx` (append five `<Composition>` registrations only)
- Create: `docs/clips/STORYBOARD.md`

- [ ] Step 1: `ClipStage` = thin wrapper over the film's `Stage` + `CaptionTrack` + narration `<Audio>` + underscore bed (ducked, reusing `mix.tsx` pattern) with a persistent, unobtrusive `REPLAY` badge component for any recreated-terminal footage.
- [ ] Step 2: Build comps per design §6 table (dimensions/durations from the clip timing data; SocialLoop fixed 240 frames, loop-safe: frame 0 state === frame 239 successor, silent — no Audio at all). Vertical is a true relayout: stacked panels, `compact` props, captions upper-third.
- [ ] Step 3: `pnpm typecheck && pnpm test`; Remotion studio spot-check via `npx remotion still` on 2–3 frames per comp; storyboard doc rows (clip → beats → frames → narration line ids). Commit `feat(clips): five launch compositions`.

### Task 10: Render, inspect, watch, report

**Files (film repo):**
- Create: `docs/clips/{RENDERS.md,QA.md,CLAIMS.md,PROVENANCE.md}`; renders in `out/clips/` (gitignored)

- [ ] Step 1: Draft renders (`--scale=0.5 --crf=26`) for all five; fix issues.
- [ ] Step 2: Final renders per repo convention (`--codec=h264` crf 18, `--timeout=120000 --concurrency=8`); `SocialLoop` also as loop-checked (first/last frame diff ≈ 0 via ffmpeg extract + compare).
- [ ] Step 3: Representative-frame inspection: `ffmpeg` extract ~1 fps contact sheets per clip; visually review every sheet; log per-clip notes in QA.md (text legibility at 100%, caption overflow, badge presence, vertical safe areas).
- [ ] Step 4: End-to-end watch log: duration/streams via ffprobe, audio present + level sanity, sheets reviewed start-to-finish; record in QA.md as the watch-through evidence.
- [ ] Step 5: CLAIMS.md final table (claim → clip+timestamp → evidence path/ref); PROVENANCE.md (every asset: source, generator, settings, date); RENDERS.md exact commands.
- [ ] Step 6: Commit `feat(clips): renders QA + claim validation + provenance` (source+docs only). Final goal report back in the infra session.

## Self-review

- Spec coverage: design §2 honesty→Global Constraints+T4/T9; §3.1→T1/T2; §3.2→T3; §3.3→T4; §3.4→T1; §3.5 phases→T4/T5; §4 matrix→T5 drills a–h cover all six mandated scenarios (plus two extra); §5→T5; §6→T7–T10; §7 risks carried in task notes. Gap check: dashboard deliberately out (design non-goal). ✓
- Placeholders: Step 1 of Task 3 contained waffling between bug variants — resolved to the literal-string bug + exact Edit swap. ✓ (fixed inline above)
- Type consistency: `executeStep` signature, transcript step shapes, `CLIP_TIMING` shape, port numbers, image name, policy name `demo`, agent name `demo-fixer` consistent across tasks. ✓
