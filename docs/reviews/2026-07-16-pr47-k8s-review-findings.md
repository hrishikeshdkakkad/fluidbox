# PR #47 review findings — Kubernetes-native provider epic

**Date:** 2026-07-16
**Target:** PR #47 (`release/kubernetes-native-provider` → `main`), head `365e657`, +6,085/−315 over 62 files
**Reviewers:** Claude (Fable 5, max effort) + Codex (GPT-5.6-sol, max reasoning), three rounds: two independent passes, one adversarial reconciliation. Every finding below was verified at file:line in the checkout; refuted candidates are recorded in the appendix so they are not re-chased.
**Verdict:** design + security posture excellent; hold merge on H1–H5. All five have small, local fixes.

Status legend: `[ ]` open · `[x]` fixed · `[-]` won't fix (record why)

---

## High severity (merge blockers)

- [x] **H1. The kind-calico CI tier has never passed — two independent causes.** *(fixed: fix/k8s-ci-green — in-cluster postgres:16 + `--wait` without `|| true`; probe targets resolved at test time by a resolver Job → ConfigMap → env)*
  Evidence: all runs of `k8s.yml` red at the probe step, incl. PR #47's latest (run 29483550211: server `CrashLoopBackOff`, "failed to lookup address information"; probe pod `Error`).
  - (a) `.github/workflows/k8s.yml:87` seeds `DATABASE_URL=postgres://stub` → server exits on DNS → no ready endpoints → positive probe leg can never connect; `helm install … || true` masks the install timeout.
  - (b) `deploy/helm/fluidbox/templates/tests/netpol-probe.yaml:14-15` resolves ClusterIPs via `lookup` at **install render time**; Helm stores rendered test hooks in the release and `helm test` re-executes them without re-rendering → on a fresh install both IPs are baked empty and the probe exits 1 before testing anything.
  - **Fix:** run a throwaway in-cluster Postgres and wait for server readiness; resolve probe targets at execution time (DNS in the test pod, or runtime query); drop the `|| true`.

- [ ] **H2. Failed terminal transition still deletes the recovery intent — permanent wedge in `finalizing`.**
  `crates/fluidbox-server/src/orchestrator.rs:373` (`collect_and_terminalize`) ignores `transition()`'s return, then reaps the sandbox, deletes workspace + archive, and `delete_finalization`s. A transient DB error on the `finalizing → terminal` UPDATE leaves the session in `finalizing` forever: `pending_finalizations` joins on the now-deleted intent row and the watchdog ignores wind-down states.
  **Fix:** delete the intent (and do destructive cleanup) only after the terminal transition is confirmed; otherwise leave the intent for the finalize worker to re-drive.

- [ ] **H3. `/result` ACKs success when intent persistence fails — the lossy-ACK bug survives on the error path.**
  `crates/fluidbox-server/src/internal.rs:846-850` awaits `orchestrator::finalize`, but `begin_finalize` swallows the `begin_finalization` DB error (logs, returns false) and the handler returns `{"ok": true}` regardless. The runner exits; no intent, no wind-down; the watchdog later fails the session — a completed run with a summary is recorded **failed**.
  **Fix:** return a retryable 5xx when the intent wasn't durably persisted (the runner contract already retries `/result`).

- [x] **H4. Any repo with a tracked symlink can never run on the K8s provider.** *(fixed: fix/k8s-symlink-archive, reworked TWICE under Codex review — the first two attempts used hand-rolled lexical/depth path math, which Codex escaped both times (symlinked-parent traversal, then a symlink-component-in-target `pivot/..`). The final design makes `canonicalize` the SOLE containment authority: it resolves the entire symlink chain, which no path arithmetic can. BOTH halves of the K8s path: (1) `unpack_archive` is two-phase — extract every real file/dir first (symlink-free tree, `safe_join` lexical path check), then create the symlinks (parent must pre-exist and canonicalize in-root, so creation never writes through an escaping link) and keep only those that `canonicalize` inside the root, dropping escapers/danglers; (2) `workspaced::copy_tree` uses the identical two-phase `canonicalize` approach to populate /workspace, preserving in-tree links and dropping those escaping the smaller /workspace root. Hardlinks and absolute-path entries still hard-refused. Tests (incl. both Codex counterexamples): `unpack_creates_intree_relative_symlink`, `unpack_drops_absolute_symlink`, `unpack_drops_escaping_symlinks_keeps_good` (covers `pivot`/`escape`), `unpack_contains_symlinked_parent_traversal`, `unpack_still_rejects_hardlink`, `symlink_survives_pack_unpack_and_appears_in_diff`, and `workspaced::copy_tree_preserves_intree_symlink_and_drops_escaping` (covers `anchor`/`leak`). NOTE: the escape ran in the per-pod, credential-free init container on the user's own repo — a containment-invariant violation, not a cross-tenant/control-plane exploit (Codex agreed); Docker bind-mounts and never uses this path.)*
  `crates/fluidbox-workspace/src/archive.rs:36` packs symlinks as entries (`follow_symlinks(false)` — correct per tar-rs guidance), but `unpack_archive` (archive.rs:112-120) rejects **every** link entry → `workspaced init` fails → run dies at init. `materialize_git` does a real checkout, so tracked symlinks are common (monorepos, dotfiles). Docker runs the same repo fine — a provider-conformance break.
  **Fix:** extract symlinks whose lexically-normalized target stays inside the workspace root; keep rejecting absolute/`..`-escaping targets and hardlinks. Add a symlink-repo fixture to the conformance tests.

- [ ] **H5. Cancel⇄result races/crash gaps apply the wrong wind-down semantics — losing caller uses its own state instead of the persisted intent's.**
  Root causes: `begin_finalize` computes `winddown`/quiesce from its own arguments after losing the `on conflict do nothing` insert (`orchestrator.rs:174-195`); `drive_finalization` keys quiesce off session status rather than `intent.needs_quiesce` (`orchestrator.rs:241-245`); intent insert + transition are non-atomic and recovery only scans wind-down statuses.
  - `/result` wins, racing cancel loses but still transitions to `Cancelling` → driver runs `await_quiesce` with the completed intent's **NULL deadline** → `unwrap_or_else(now)` = instant "timeout" → collection skipped → **completed run loses its diff** to `artifact_missing(quiesce_timeout)`.
  - Cancel inserts `needs_quiesce=true`, server crashes before the `Cancelling` transition → runner never receives quiesce; a later budget/result caller drives the recorded cancellation without quiescing.
  - **Fix:** on losing the insert, reload the winning intent and derive transition, deadline, and quiesce exclusively from that row; make recovery consider intents whose sessions are still in active states.

## Medium severity

- [ ] **M1. Budget/fail finalizations collect from a live, still-writing worktree.**
  Design doc's "unified sequence for ALL terminal paths" includes "await runner-container termination → collect"; `SandboxStatus::is_live` doc agrees — but only the Cancelling path waits. `workers.rs:165` (budget) and `fail()` collect immediately; a runner mid-`Bash` yields a torn diff stored as the authoritative audit artifact.
  **Fix:** extend the quiesce/await step to all paths with a live sandbox (bounded wait for `!is_live()`).

- [x] **M2. Exec collection has no integrity checking.** *(fixed: fix/k8s-collect-integrity — (1) `collect.rs` computes header `bytes`/`sha256` over the stored lossy-UTF-8 patch bytes, not raw git stdout; (2) `parse_collected` splits body on raw bytes and verifies length + digest against the header — a short or corrupted body is an explicit Missing, never a silent truncated diff; (3) `exec_collect` reads the remote exit via `take_status()` (draining stdout+stderr concurrently) and surfaces a non-zero exit as Err; (4) `collect_stream_with_resume` re-execs `workspaced stream --offset <got>` on a short read, bounded by MAX_STREAM_RESUMES. Tests: diff_integrity_describes_stored_bytes_not_raw, parse_short_body_is_missing_not_silent, parse_corrupted_body_is_missing, parse_verifies_non_utf8_body_byte_exactly, stream_target_reads_ok_header_only.)*
  `crates/fluidbox-provider-k8s/src/lib.rs:~409` (`exec_collect`): `let _ = proc.join()` — kube's `join()` carries transport errors only; remote exit status via `take_status()` is never read (the adjacent comment is untrue). `parse_collected` never compares body vs the header's own `bytes=`/`sha256=`; `workspaced stream --offset` resume is dead code. A cleanly-closed-early stream stores a truncated diff.
  **Interacting bug:** the header's `bytes`/`sha256` are computed over raw git stdout while the streamed body is the lossy-UTF-8 patch (`collect.rs:~164`) — compute them over the stored bytes, then verify body vs header and resume via `--offset` on mismatch.

- [ ] **M3. Helm advertises sandbox knobs the provider never receives; tolerations are dead code; probe placement diverges.**
  `templates/server.yaml` wires none of `values.sandbox.{resources,runAsUser,volumeSizeLimit,nodeSelector,priorityClassName}` into `FLUIDBOX_K8S_*`; `K8sConfig::from_env` hardcodes `tolerations: Vec::new()` (`config.rs:74`). The Rust boot-gate probe (`netpol.rs:70-88`) carries none of the sandbox scheduling/runtimeClass config (helm-test probe does) — gate can pass on a pool sandboxes don't run on, or block on tainted pools.
  **Fix:** wire values → env; add a tolerations env format; give the boot probe the sandbox placement config; add a chart test asserting values→PodSpec.

- [ ] **M4. Whole-archive-in-RAM on a 1 Gi pod.**
  `archive.rs:33-57` builds the entire tar.gz in a `Vec` with no ceiling; `pack_and_store_archive` holds it again; `internal.rs:776` serves via `tokio::fs::read`. Large repo → control-plane OOM at run creation.
  **Fix:** stream pack to disk (`GzEncoder<File>`), stream the HTTP response (`ReaderStream`), add a max-archive-bytes cap that fails the run cleanly.

- [ ] **M5. Reconciliation is boot-only, never adopts — crash window creates a session invisible to every sweeper at once.**
  `list_managed` only from `boot_orphan_sweep` (`workers.rs:19`), despite design promising periodic reconcile + adoption. Interaction: crash after runner start but before `set_sandbox_handle` → heartbeats refresh `updated_at` (`fluidbox-db/src/lib.rs:1757`) so `stale_nonstarted_sessions` never fires; boot sweep skips (session live, no adoption); budget sweeper scans only `running`/`awaiting_approval` → pod `activeDeadlineSeconds` is the only brake. Also: cancel-during-provisioning reaps before the handle lands → pod leaks until next restart.
  **Fix:** periodic managed-pod reconcile that adopts or terminates; enforce launch-age from timestamps heartbeats can't refresh.

- [ ] **M6. `CreateContainerConfigError` classified fatal, but Pod-first/Secret-second guarantees a window that produces it.**
  `fatal_waiting` (`provider-k8s/src/lib.rs:196-205`) kills the pod on a reason the kubelet emits transiently while the Secret doesn't exist yet — which is by design here.
  **Fix:** grace-window this reason; fatal only if it persists after the Secret verifiably exists.

- [ ] **M7. Node loss maps to a live status forever.**
  `runner_status` falls through phase `Unknown`/stale statuses to `Pending`/`Running`; `metadata.deletion_timestamp` never consulted → `sandbox_dead` stays false with stale heartbeats; a budget-less run hangs indefinitely.
  **Fix:** map node-loss/Unknown/deletion-in-progress to `SandboxStatus::Unknown`.

- [ ] **M8. Public listener still serves `/internal`; chart Ingress exposes it to the internet.**
  Deliberate for Docker single-host, but on K8s it undercuts the design's "route absence is stronger than bearer auth" rationale (`main.rs` public router nests `internal.clone()`; `templates/ingress.yaml` routes `/` to :8787).
  **Fix:** make mounting `/internal` on the public router conditional (off for `provider=kubernetes`).

- [ ] **M9. OOTB `helm install` from the OCI registry can't work.**
  Default tags `:dev` (values.yaml) are never published by `release.yml` (pushes digests + `:latest`); templates can't render `repo@sha256:` for the deployment images.
  **Fix:** bind release tags/digests into the packaged chart; support digest rendering.

- [ ] **M10. Sandbox/probe pods have no `imagePullSecrets` support.**
  `values.images.pullSecrets` applies only to Deployments; private runner/collector images fail in the sandbox namespace (`manifest.rs`, `netpol.rs`).
  **Fix:** add pull-secret refs to `K8sConfig` + both PodSpecs; document the Secret must exist in the sandbox namespace.

## Low severity

- [ ] **L1.** `workspace_archive` gates on `is_terminal()` while its comment (and every sibling endpoint) says `accepts_work()` (`internal.rs:768-772`).
- [ ] **L2.** Netpol gate: ClusterIP-resolution failure branch doesn't clear a previously-true gate yet keeps the 6-hour interval (`workers.rs:250-256`) — inconsistent with the probe branch (which stores `false`); `interval`'s immediate first tick = one redundant probe.
- [ ] **L3.** `delete_archive`'s "TTL sweep is the backstop" comment references a sweep that doesn't exist; archives kept until terminal cleanup (design said delete-after-init-consumed); crash after terminal transition but before `remove_file` leaks the archive permanently.
- [x] **L4.** Untrue/garbled comments: ~~`pack_workspace` says symlinks "are followed" while code sets `follow_symlinks(false)`~~ *(fixed batch 3)* (ties to H4); ~~`exec_collect` claims exit codes are surfaced~~ *(fixed batch 4: `exec_collect` now actually reads the exit via `take_status()` and the comment matches)* (ties to M2).
- [ ] **L5.** `FLUIDBOX_INTERNAL_BIND` defaults to `0.0.0.0:8788` even for `provider=docker` local dev — new LAN-exposed listener by default.
- [ ] **L6.** `await_quiesce` checks the deadline before ever probing state (`orchestrator.rs:277-280`) — crash-recovery with an expired deadline records `quiesce_timeout` even when the runner exited cleanly in time; one `state()` check first rescues the diff.
- [ ] **L7.** `finalize()` passes `summary` as both summary and status reason.
- [ ] **L8.** `main.rs:99` hardcodes `:8788` in the resolved ClusterIP URL rather than deriving from config; URL also unbracketed for IPv6 ClusterIPs (breaks IPv6-primary clusters).
- [ ] **L9.** K8s pre-launch failures with a materialized workspace record a noise `(diff unavailable: no sandbox handle…)` artifact where Docker records "(no changes)" (`expected_diff` keys off `base_commit`).
- [ ] **L10.** UID hardening: `delete_pod` accepts `uid=None` (unguarded delete); exec collection never re-checks pod UID. Defense-in-depth only — handles always carry UIDs today.
- [ ] **L11.** Claude runner: heartbeats start (`index.mjs:62`) before `onQuiesce` registers (`:126`), and `contract.mjs` latches `quiesced=true` even with a null callback — a cancel in that seconds-wide window is permanently swallowed (codex-runner registers first; safe). Fix: register before `startHeartbeat`, or replay on registration.
- [ ] **L12.** Chart Ingress routes `/` to the API server while NOTES.txt tells the operator that URL is the dashboard; web Service unreachable via the chart's Ingress.
- [ ] **L13.** Test-coverage gaps (beyond H1): ~~no symlink-repo fixture (H4)~~ *(batch 3: archive + copy_tree + symlinked-parent-escape fixtures)*, no cancel⇄result race test (H5), ~~no truncated-exec-stream test (M2)~~ *(batch 4)*, no values→PodSpec chart test (M3).
- [x] **L14.** *(found during batch 1; fixed in batch 1 — it was a live merge blocker, not a latent one)* `fluidbox-db` test `stale_nonstarted_sweep_finds_only_old_prelaunch_sessions` still drove the pre-epic direct `Created→Failed` edge; Phase 0's wind-down machine made terminal reachable only via `Finalizing` (state.rs:113), so `transition_session` no-ops (`Ok(None)`), the session stays `created`, and the "terminal session must not be swept" assertion fails. **ci.yml's `rust` job runs a postgres:16 service container, so this test RUNS in CI — the job had been red on the release branch since Phase 0 merged** (and on every fix PR since, incl. #58/#59). Fixed: the test now asserts the direct edge is REFUSED, terminalizes legally via `Finalizing→Failed`, additionally asserts winding-down sessions aren't swept, and deletes its fixtures BEFORE the assertions (a failed assertion no longer leaks sessions). Pass verified against a throwaway local postgres:16 replicating the CI job; the watchdog's real fail path rides `orchestrator::fail` → finalize and was never affected.

---

- [ ] **L15. (opened batch 3, Codex v4/v5)** The workspace extractor/copy is not fully symlink-safe against an **attacker-controlled destination path**. `clear_dir_contents`' guard checks only the final path component, so a symlinked ancestor (`parent_link/dest`), a trailing-slash spelling (`dest/`), or a TOCTOU swap between check and use can still make it operate through a symlink to outside the root. **Not production-reachable** — production `dest` is a fixed pod-spec mount (`/workspace`, `/collector/…`) the runner cannot re-point, and same-run + lifecycle-replay escapes (the real risks) ARE fixed. Closing this residual robustly needs kernel-enforced resolution (`openat2 RESOLVE_IN_ROOT` on Linux, or `cap-std`/`openat`) rather than more userspace path math — a dependency/platform decision for the maintainer. Five hand-rolled rounds proved userspace lexical guards are the wrong tool here.

## Suggested fix batches (one `fix/*` PR into the release branch each, matching #58/#59 precedent)

1. **`fix/k8s-ci-green`** — H1 (in-cluster Postgres + runtime probe resolution + drop `|| true`). Do this first: it turns CI into a real check for everything after.
2. **`fix/k8s-finalizer-durability`** — H2, H3, H5, M1, L6, L7 (+ the H5 intent-atomicity: derive everything from the winning intent row; recovery scans active-status intents). One coherent workstream — all in `begin_finalize`/`drive_finalization`/`collect_and_terminalize`/`/result`. (L14 was pulled forward into batch 1 — it was blocking every PR's `rust` check.)
3. **`fix/k8s-symlink-archive`** — H4 + L4(pack comment) + symlink conformance fixture.
4. **`fix/k8s-collect-integrity`** — M2 (+ compute header sha/bytes over stored bytes; wire `--offset` retry) + L4(exec comment).
5. **`fix/k8s-helm-wiring`** — M3, M9, M10, L12 (+ chart test).
6. **`fix/k8s-archive-streaming`** — M4 + pack-size cap + L3 (real TTL sweep, delete-after-init).
7. **`fix/k8s-reconcile`** — M5, M6, M7, L9 (+ periodic sweep, adoption, deletion_timestamp).
8. **`fix/k8s-listener-hardening`** — M8, L1, L5, L8.
9. **`fix/k8s-cleanups`** — L2, L10, L11 and any remaining comment fixes.

## Acceptance before merging #47

- [ ] `just check` green on the release branch
- [ ] `k8s.yml` kind-calico job green (first time ever) — including `helm test` passing on a **fresh** install
- [ ] Full Docker e2e green (`FLUIDBOX_PROVIDER=docker`) — maintainer-triggered
- [ ] Live EKS acceptance + teardown (still deferred per epic plan; design doc's acceptance statement requires demo A on kind **and** one managed cloud)
- [ ] Symlinked-repo run passes on the K8s provider

## Appendix — refuted candidates (do NOT re-chase)

- **OAuth advisory-lock stale read:** `refresh_access_token` re-reads the sealed refresh token from the DB inside the lock (`oauth.rs:817`); cross-replica rotation is correct.
- **tar `preserve_permissions(false)` strips exec bits:** tar-rs applies `mode & 0o777` when preserve=false — exec bits survive; only setuid/sgid dropped (verified in tar-0.4.46 source).
- **Secret-create failure leaves the pod:** provision DOES best-effort `delete_pod(name, Some(uid))` on that path (`provider-k8s/src/lib.rs:231-236`). (Codex conceded.)
- **Netpol gate flipping closed on transient probe errors:** working-as-designed fail-closed policy (only the resolution-branch inconsistency remains, tracked as L2).
- Pod-first/Secret-second ordering, UID preconditions, ownerRef GC, restricted-PSS compliance of sandbox + probe pods, and the wind-down state machine (no active→terminal edge) all held up under adversarial reading.

## Collaboration record

Codex (gpt-5.6-sol, max reasoning, read-only sandbox) produced 27 independent findings: 1 refuted with source evidence, 3 downgraded/narrowed, rest confirmed. Claude produced 17: 16 confirmed by Codex, 1 withdrawn as working-as-designed. The two High-grade interaction bugs (H5's null-deadline race; M5's invisible-session window) were found by neither reviewer alone — they emerged in reconciliation. Four additional early candidates were self-refuted before ever being reported.
