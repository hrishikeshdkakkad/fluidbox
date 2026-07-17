# Continuance handover — PR #47 fix series, batches 5–7

**Written:** 2026-07-16, end of a long fix session. **Mission:** finish the
PR #47 (`release/kubernetes-native-provider` → `main`) fix series — batches
**5, 6, 7** from `docs/reviews/2026-07-16-pr47-k8s-review-findings.md` — until
all High+Medium findings are `[x]` (or `[-]` with maintainer sign-off), each
in its own stacked `fix/*` PR. Read the original workflow rules in
`docs/reviews/2026-07-16-pr47-fix-handover.md` FIRST; they still bind.

## State (what's done)

- **#60 MERGED** to the release branch — batch 1 (H1 CI + L14).
- **PR #61** batch 3 (`fix/k8s-symlink-archive`, tip `0e2ddc4`) — H4 symlink
  support + L4-pack. Five Codex rounds; **canonicalize** is the sole
  containment authority + fail-closed fresh-dest clearing. ACCEPTED with one
  tracked residual **L15** (symlinked-*dest*-path hardening; NOT production-
  reachable — fixed pod mounts; needs `openat2 RESOLVE_IN_ROOT`/`cap-std`, a
  maintainer dependency decision — do NOT hand-roll it). Do not reopen H4.
- **PR #62** batch 4 (`fix/k8s-collect-integrity`, tip `7c7de42`, stacked on
  #61) — M2 collect integrity + L4-exec.
- **Batch 2** (H2/H3/H5/M1/L6/L7 finalizer) is a SIBLING session's branch
  `fix/k8s-finalizer-durability` (`4b9d162`, in the main checkout, not yet
  PR'd). DO NOT touch it.
- **Batch 5 WIP** on `fix/k8s-helm-wiring` (stacked on #62): only
  `crates/fluidbox-provider-k8s/src/config.rs` done so far — `Toleration`
  now `Deserialize`s; `from_env` parses `FLUIDBOX_K8S_TOLERATIONS` (JSON
  array) and `FLUIDBOX_K8S_IMAGE_PULL_SECRETS` (comma list); new
  `image_pull_secrets` field; unit tests present.

All HIGH merge-blockers resolved (H1 #60, H4 #61, H2/H3/H5 in batch 2). The
findings doc has live `[x]` checkboxes — flip them per batch, in the same PR.

## Hard rules (unchanged)

1. NEVER run DB-backed or e2e tests, and never `source .env`, unprompted.
2. Never merge PRs, never push to `main`. Open stacked `fix/*` PRs; hand back.
3. Dual-provider permanence: never break the Docker provider / docker-compose.
4. One PR per batch, in the findings doc's batch order; each stacked on the
   previous fix branch for a clean incremental diff.
5. Every batch flips its findings checkboxes AND needs a fail-before/pass-after
   test for each High/Medium fix (TDD).
6. Codex adversarial pass on each batch's diff before hand-back (protocol in
   the original handover). It found REAL escapes 5× on batch 3 — trust it,
   but verify each claim at file:line yourself.

## Gotchas learned THIS session (important)

- **`just` loads `.env` (`set dotenv-load := true`)** → `just check` runs the
  fluidbox-db suite against REAL Neon. Use the no-dotenv equivalents:
  `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D
  warnings`, `cargo test -p <crate>`. Confirm `DATABASE_URL` is unset first.
- **Disk was 100% full mid-session.** Point cargo at the main target dir to
  avoid duplicating the dep graph:
  `export CARGO_TARGET_DIR=/Users/hrishikeshkakkad/Documents/infra/target CARGO_INCREMENTAL=0`.
- **BRANCH-SLIP: I committed batch-3 fixes onto the batch-5 branch TWICE**
  after a cascade left me on the wrong branch. ALWAYS `git branch --show-current`
  before editing/committing. Fix via `git stash` → checkout right branch →
  `stash pop`, or cherry-pick the misplaced commit and `reset --hard` the
  source.
- **Rebase cascade after changing a lower batch:** `git rebase --onto
  <new-lower-tip> <old-lower-tip> <upper-branch>`, `--force-with-lease` push,
  repeat up the stack. Conflicts appear in `collect.rs` (test region) and the
  findings doc (checkbox lines) — keep BOTH sides' intent.
- **Codex CLI:** `codex exec -c sandbox_mode="read-only" "$PROMPT" < /dev/null
  > out.md 2> err.log`, run in BACKGROUND (max-reasoning turns exceed 1800s;
  `< /dev/null` stops a stdin hang). Do NOT override the model.

## Remaining work

**Batch 5 `fix/k8s-helm-wiring` (M3, M9, M10, L12):** `build_pod` already
consumes the full `K8sConfig`. Remaining: wire `values.sandbox.*` →
`FLUIDBOX_K8S_*` env in `deploy/helm/fluidbox/templates/server.yaml`
(resources, run_as_user, volume_size_limit, node_selector, priority_class,
`FLUIDBOX_K8S_TOLERATIONS` via `toJson`, `FLUIDBOX_K8S_IMAGE_PULL_SECRETS`);
apply `imagePullSecrets` to the sandbox PodSpec in `manifest.rs` and the
boot-probe PodSpec in `netpol.rs`; give the netpol boot probe the sandbox
placement (nodeSelector/tolerations/runtimeClass/priorityClass) — M3's gate-
parity gap; M9: bind release tags/digests into the packaged chart + support
`repo@sha256:` rendering; M10: pull-secret refs on both PodSpecs; L12: chart
Ingress routes `/` to the API while NOTES.txt says dashboard — fix web routing.
Add a values→PodSpec chart test (L13). Verify: `helm lint` + `helm template`
each preset (kind/eks/gke/aks/doks).

**Batch 6 `fix/k8s-archive-streaming` (M4, L3):** stream pack to disk
(`GzEncoder<File>`), stream the HTTP response (`ReaderStream`), max-archive-
bytes cap failing the run at zero model spend; real TTL sweep + delete-after-
init; fix crash-window archive leak.

**Batch 7 `fix/k8s-reconcile` (M5, M6, M7, L9):** periodic `list_managed`
sweep that terminates terminal/unknown-session pods and ADOPTS handle-less
pods (set handle after UID validation); launch-age off timestamps heartbeats
can't refresh; M6 grace-window `CreateContainerConfigError`; M7 map node-loss/
Unknown/deletion_timestamp → `SandboxStatus::Unknown`; L9 pre-launch-with-
workspace records "(no changes)" like Docker.

Plus remaining Lows (L1/L2/L5/L8/L10/L11) as a final `fix/k8s-cleanups` batch.

## Merge order & done

Children-first: #61 → #62 → 5 → 6 → 7 → then #47 → `main` (PR-only ruleset;
`gh pr merge --admin`). Done when all H+M are `[x]`/signed-off, `just check`
green on the release branch, kind-calico CI green, no Docker-path regression —
then hand back for the maintainer's Docker e2e + live EKS acceptance + the #47
merge. This handover doc + L15 can be deleted before batch 5's final PR.
