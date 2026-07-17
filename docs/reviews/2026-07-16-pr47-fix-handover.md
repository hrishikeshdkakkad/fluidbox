# Session handover — fix PR #47 review findings (with Codex)

## Mission

Work through `docs/reviews/2026-07-16-pr47-k8s-review-findings.md` batch by batch until PR #47 (`release/kubernetes-native-provider` → `main`) is merge-ready: all High findings fixed, Mediums fixed or explicitly deferred with my sign-off, checkboxes updated. Codex (GPT-5.6-sol, max reasoning) is your adversarial verifier on every batch — findings in that doc were produced jointly by Claude + Codex and every fix goes back through Codex before it ships.

## Context you need

- Repo: `/Users/hrishikeshkakkad/Documents/infra` (fluidbox). Read `CLAUDE.md` first; `PLAN.md` §2 invariants bind every change.
- The epic: K8s-native provider, design doc `docs/plans/2026-07-15-kubernetes-native-provider-design.md`. PR #47 is the release-branch PR; phases 0–3 already merged into `release/kubernetes-native-provider` (head `365e657`).
- The worklist: `docs/reviews/2026-07-16-pr47-k8s-review-findings.md` — 5 High / 10 Medium / 13 Low, each verified at file:line, with fix hints, ordered fix batches, and a refuted-candidates appendix (do NOT re-investigate anything in that appendix).
- Precedent for fix PRs: #58 (`fix/k8s-rustls-crypto-provider`), #59 (`fix/k8s-litellm-numeric-user`) — small branches off the release branch, PR'd into the release branch, conventional-commit style `fix(k8s): …`.
- `scripts/eks-teardown.sh` is untracked and NOT part of this work — leave it alone.
- The findings doc and this handover may still be untracked — commit both to the release branch as the first change of batch 1 so checkbox updates are tracked.

## Hard rules (non-negotiable)

1. **NEVER run DB-backed or e2e tests unprompted.** `just e2e`, `scripts/governance-e2e.sh`, and anything requiring `source .env` hit REAL Neon and spend REAL Anthropic money — I trigger those myself. Never `set -a; source .env` before tests. ~~Plain `just check` is safe (the DB test self-skips without `DATABASE_URL` exported).~~
   **⚠ Correction (2026-07-16, batch 1):** `justfile:1` sets `set dotenv-load := true`, so EVERY `just` recipe — including `just check` — loads `.env` and the fluidbox-db tests RUN against real Neon on a machine with a populated `.env`. Batch 1 tripped this and hit the pre-existing L14 test failure (fixtures leaked; `just db-clean-tests` is the remedy, maintainer-triggered). Use the explicit equivalents instead, which never load `.env`: `cargo fmt --all --check` && `cargo clippy --workspace --all-targets -- -D warnings` && `cargo test --workspace` && `(cd apps/web && pnpm test && pnpm build)`.
2. **Never merge PRs and never push to `main`.** Open PRs into `release/kubernetes-native-provider` and hand back. `main` is PR-only via ruleset.
3. **Dual-provider permanence:** nothing may break the Docker provider or the docker-compose path. Any shared-code change (orchestrator, workers, internal, fluidbox-workspace) must keep Docker semantics intact.
4. One PR per batch, batches in the doc's order. If the previous batch's PR is unmerged when you start the next, branch off the previous fix branch and say so in the PR body.
5. Every batch updates its findings' checkboxes to `[x]` in the findings doc, inside the same PR.

## Batch workflow (repeat per batch, in doc order)

1. `git checkout release/kubernetes-native-provider && git pull`, then branch `fix/k8s-<batch-name>` (names are in the doc's "Suggested fix batches").
2. Re-read the batch's findings in the doc AND the referenced code — line numbers may have drifted; the finding text carries the mechanism.
3. For **batch 2 (finalizer durability) only**: before writing code, send Codex your proposed approach (see protocol below) and reconcile — that batch is race-sensitive and the doc's principle is load-bearing: *the persisted `session_finalizations` row is the single source of truth; losing callers reload it; recovery scans intents regardless of session status; nothing destructive happens until the terminal transition is confirmed.*
4. Implement, with tests: every High/Medium fix needs a test that fails before and passes after (the doc's L13 lists the specific missing tests: symlink-repo fixture, cancel⇄result race, truncated-exec-stream, values→PodSpec chart assertion).
5. Verify locally: `cargo fmt --all --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test -p fluidbox-core -p fluidbox-workspace -p workspaced -p fluidbox-provider-k8s`, plus `just check` at the end. For chart batches: `helm lint deploy/helm/fluidbox` + `helm template` with each values preset.
6. **Codex adversarial pass on the diff** (protocol below). Verify every Codex claim in source yourself before acting on it — it conceded findings this round when challenged with evidence; do the same back.
7. Commit(s) `fix(k8s): <what>`, push, `gh pr create` into `release/kubernetes-native-provider`. After batch 1 lands, the kind-calico CI job is a real signal — watch it with `gh pr checks` and don't hand back a red one without explaining why.
8. Hand back: PR URL, finding IDs fixed, test evidence, CI status, anything new discovered (append new findings to the doc, unchecked).

## Codex collaboration protocol (learned the hard way — follow exactly)

- **Do NOT use the `mcp__codex__codex` MCP tool for long turns.** It aborts after 1800 s of silence and a max-reasoning turn routinely thinks longer — a 31-minute review turn was killed mid-reasoning this way. Use the CLI via Bash with `run_in_background: true`:
  ```bash
  codex exec -c sandbox_mode="read-only" "<prompt>" > <scratchpad>/codex-out.md 2> <scratchpad>/codex-err.log
  ```
  Defaults from `~/.codex/config.toml` are already `model = "gpt-5.6-sol"`, `model_reasoning_effort = "max"` — do not override the model. DO pass `-c sandbox_mode="read-only"` (the config default is danger-full-access).
- Continue a Codex session (keeps its context): `codex exec resume <SESSION_ID> -c sandbox_mode="read-only" "<prompt>"`. The session id is in the stderr banner and in `~/.codex/sessions/YYYY/MM/DD/rollout-*.jsonl`. If a turn ever gets killed, its research survives in the session — resume it and ask it to "output what you already established" instead of re-running.
- Keep each Codex turn scoped to ONE batch's diff so turns stay short. Review-pass prompt shape that worked:
  - give it the branch diff (`git diff release/kubernetes-native-provider...HEAD > <scratchpad>/batch.diff`) and the repo path;
  - state the findings the batch claims to fix (paste their text from the doc);
  - instruct: "For each claimed fix: verify at file:line that the mechanism is actually closed, and actively try to REFUTE it (race it, crash it mid-way, feed it hostile input). Then hunt regressions in the touched files, Docker path included. Verdict per item: FIXED / NOT-FIXED / NEW-DEFECT, evidence-first, findings only."
- Disagreements: challenge with file:line evidence in a `resume` turn; drop any claim neither of you can evidence in source.

## Batch-specific load-bearing notes

- **Batch 1 (CI):** two independent causes — both must be fixed. Real in-cluster Postgres (a `postgres:16` Deployment+Service in the kind cluster is fine; the server runs sqlx migrations on boot), wait for server readiness, drop `|| true`. The helm-test probe must resolve targets at RUN time — Helm renders test hooks at install and stores them, so `lookup` at render time is baked-empty on fresh installs; DNS from inside the test pod works because the test pod does not need the zeroEgress profile applied... verify it does not carry the sandbox egress label if you switch to DNS, or resolve via an initContainer/env another way. Prove it: fresh `helm install` → `helm test` green in CI.
- **Batch 2 (finalizer):** the H5 fix decides most of it — on `begin_finalization` conflict, reload the winning row and derive transition/deadline/quiesce from it; make `pending_finalizations` also return intents whose sessions are still in active statuses; `collect_and_terminalize` must not delete the intent (or any evidence) unless `transition()` returned true or the session is verifiably terminal; `/result` returns 5xx if the intent wasn't durably persisted (runner retries). M1: bounded wait for `!is_live()` on ALL collect paths, not just Cancelling. L6: one `state()` probe before declaring quiesce timeout.
- **Batch 3 (symlinks):** extend `unpack_archive` to create symlink entries whose lexically-normalized target (join of entry dir + link target, no fs access) stays inside the dest root; keep rejecting hardlinks and absolute/escaping targets; fixture = a git repo with an in-tree relative symlink, asserted through pack→unpack→collect.
- **Batch 4 (collect integrity):** compute the header's `bytes`/`sha256` in `workspaced diff` over the exact stored file bytes (post-lossy); provider verifies body length+digest against the header and re-execs `stream --offset <got>` on shortfall (bounded retries) before recording Missing; read exec exit via `take_status()`.
- **Batch 6 (streaming):** stream pack to disk, stream the GET response, add a max-archive-bytes cap that fails the run with a clear reason at zero model spend, and add the TTL sweep the comment already promises.
- **Batch 7 (reconcile):** periodic `list_managed` sweep that (a) terminates pods of terminal/unknown sessions, (b) ADOPTS handle-less pods into live sessions (set handle after UID validation) — closing the invisible-session window (M5): launch-age enforcement must key off timestamps heartbeats can't refresh.

## Definition of done

All High + Medium checkboxes `[x]` (or `[-]` with my explicit sign-off recorded in the doc), Lows fixed or consciously deferred, `just check` green, kind-calico CI green on a fresh install, no Docker-path regression in the unit tiers. Then hand back for: my Docker e2e run, the live EKS acceptance (deferred per epic plan), and the #47 merge decision. Do not run any of those three yourself.
