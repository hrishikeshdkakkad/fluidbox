//! Hardened terminal diff collection.
//!
//! Principle (design 2026-07-15): **never execute git against
//! agent-controlled `.git` state — on any provider.** An agent can write
//! `diff.external`, clean/smudge filters, `core.fsmonitor`, or hooks into
//! its workspace's `.git`; running plain `git diff` there executes attacker
//! code on whatever machine collects.
//!
//! Instead, collection reconstructs a throwaway repository from the
//! PRISTINE baseline (the `.git` saved at materialization, before the agent
//! ever ran) pointed at the final worktree, and runs git with a scrubbed
//! environment: no system/global config, no hooks, no fsmonitor, no
//! external diff, no prompts, controlled HOME. Output is bounded in size
//! and the child is killed on a deadline — a hostile worktree can waste the
//! cap, never the collector.

use crate::{WorkspaceError, BASELINE_DIR};
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Bounds on one collection run.
#[derive(Debug, Clone)]
pub struct DiffCaps {
    /// Stored diff ceiling; larger output is truncated and flagged.
    pub max_bytes: usize,
    /// Per-git-invocation wall-clock ceiling (the child is killed past it).
    pub git_timeout: Duration,
}

impl Default for DiffCaps {
    fn default() -> Self {
        Self {
            max_bytes: 8 * 1024 * 1024,
            git_timeout: Duration::from_secs(90),
        }
    }
}

#[derive(Debug)]
pub struct CollectedDiff {
    /// Unified `--binary` patch text (lossy UTF-8; possibly truncated).
    pub patch: String,
    pub truncated: bool,
    /// Size in bytes of the stored (post-truncation) content.
    pub bytes: u64,
    /// Digest of the stored content.
    pub sha256: String,
}

/// Collection either produces a (possibly empty) diff, or an EXPLICIT
/// missing marker — never a silent "(no changes)".
#[derive(Debug)]
pub enum CollectionOutcome {
    Diff(CollectedDiff),
    Missing { reason: String },
}

/// Collect the agent's changes from a session workspace root
/// (`<data_dir>/workspaces/<sid>`) laid out as `repo/` + `baseline-git/` —
/// the Docker host-dir layout. Delegates to [`collect_diff_at`].
pub fn collect_diff(
    workspace_root: &Path,
    base_commit: Option<&str>,
    caps: &DiffCaps,
) -> CollectionOutcome {
    let repo = workspace_root.join("repo");
    let baseline = workspace_root.join(BASELINE_DIR);
    let scratch_root = workspace_root.to_path_buf();
    collect_diff_at(&repo, &baseline, &scratch_root, base_commit, caps)
}

/// Collect a diff from explicit worktree + pristine-baseline paths, using a
/// scratch dir under `scratch_root`. This is the layout-agnostic core: the
/// Docker path passes `<root>/repo` + `<root>/baseline-git`; the in-pod
/// collector passes `/workspace` + `/collector/baseline` (different mounts,
/// same hardened engine).
pub fn collect_diff_at(
    worktree: &Path,
    baseline: &Path,
    scratch_root: &Path,
    base_commit: Option<&str>,
    caps: &DiffCaps,
) -> CollectionOutcome {
    if !worktree.is_dir() {
        return CollectionOutcome::Missing {
            reason: "workspace worktree missing (never materialized, or already cleaned)".into(),
        };
    }
    if !baseline.is_dir() {
        return CollectionOutcome::Missing {
            reason: "pristine baseline missing — refusing to touch the agent-controlled .git"
                .into(),
        };
    }
    match collect_inner(scratch_root, worktree, baseline, base_commit, caps) {
        Ok(diff) => CollectionOutcome::Diff(diff),
        Err(e) => CollectionOutcome::Missing {
            reason: format!("collection failed: {e}"),
        },
    }
}

fn collect_inner(
    scratch_root: &Path,
    worktree: &Path,
    baseline: &Path,
    base_commit: Option<&str>,
    caps: &DiffCaps,
) -> Result<CollectedDiff, WorkspaceError> {
    // Scratch space lives INSIDE the scratch root (cleaned with it) but
    // outside the worktree (never visible to any sandbox transport).
    let scratch = scratch_root.join("collect-tmp");
    if scratch.exists() {
        std::fs::remove_dir_all(&scratch)?;
    }
    let git_dir = scratch.join("git");
    let home = scratch.join("home");
    let hooks = scratch.join("hooks"); // exists and is empty — hooksPath target
    std::fs::create_dir_all(&home)?;
    std::fs::create_dir_all(&hooks)?;
    crate::copy_dir_all(baseline, &git_dir)?;
    // A stale lock from a crashed materialization must not wedge collection.
    std::fs::remove_file(git_dir.join("index.lock")).ok();

    let result = (|| {
        // Stage everything the agent produced (into OUR index), then diff
        // against the base. --ignore-errors: an unreadable file skips, it
        // doesn't forfeit the whole diff.
        let add = run_git_scrubbed(
            &git_dir,
            worktree,
            &home,
            &hooks,
            &["add", "-A", "--ignore-errors"],
            64 * 1024,
            caps.git_timeout,
        )?;
        if !add.ok() {
            return Err(WorkspaceError::Git(format!(
                "git add -A: {}",
                add.describe()
            )));
        }

        let base = base_commit.unwrap_or("HEAD");
        let diff = run_git_scrubbed(
            &git_dir,
            worktree,
            &home,
            &hooks,
            &["diff", "--binary", "--no-color", "--no-ext-diff", base],
            caps.max_bytes,
            caps.git_timeout,
        )?;
        if !diff.ok() {
            return Err(WorkspaceError::Git(format!(
                "git diff {base}: {}",
                diff.describe()
            )));
        }

        let truncated = diff.stdout_truncated;
        // The stored artifact is the lossy-UTF-8 patch text. Integrity metadata
        // MUST describe those exact stored bytes, NOT the raw git stdout: the
        // collector's `stream` consumer verifies the received body against this
        // header, so any raw/stored divergence (git output with invalid UTF-8)
        // would otherwise make every such diff fail verification. When git
        // output is valid UTF-8 — the common case — the two are identical.
        let patch = String::from_utf8_lossy(&diff.stdout).into_owned();
        let sha256 = {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(patch.as_bytes());
            format!("sha256:{}", hex::encode(h.finalize()))
        };
        Ok(CollectedDiff {
            bytes: patch.len() as u64,
            patch,
            truncated,
            sha256,
        })
    })();

    std::fs::remove_dir_all(&scratch).ok();
    result
}

struct BoundedOutput {
    status: Option<i32>,
    timed_out: bool,
    stdout: Vec<u8>,
    stdout_truncated: bool,
    stderr_head: String,
}

impl BoundedOutput {
    fn ok(&self) -> bool {
        !self.timed_out && self.status == Some(0)
    }
    fn describe(&self) -> String {
        if self.timed_out {
            return "killed on collection deadline".into();
        }
        format!(
            "exit {:?}: {}",
            self.status,
            self.stderr_head
                .trim()
                .chars()
                .take(400)
                .collect::<String>()
        )
    }
}

/// Run git against the throwaway GIT_DIR + the agent worktree with a fully
/// scrubbed environment, bounded stdout, and a kill-on-deadline watchdog.
fn run_git_scrubbed(
    git_dir: &Path,
    worktree: &Path,
    home: &Path,
    empty_hooks: &Path,
    args: &[&str],
    max_out: usize,
    timeout: Duration,
) -> Result<BoundedOutput, WorkspaceError> {
    let mut cmd = Command::new("git");
    cmd
        // Belt and braces on top of the pristine config: even if a hostile
        // value somehow reached the baseline, these -c overrides win.
        .arg("--no-pager")
        .arg("-c")
        .arg(format!("core.hooksPath={}", empty_hooks.display()))
        .arg("-c")
        .arg("core.fsmonitor=false")
        .arg("-c")
        .arg("gc.auto=0")
        .args(args)
        .current_dir(worktree)
        // env_clear drops every ambient GIT_*/agent-set variable; git then
        // sees ONLY what we hand it. PATH survives so `git` subprocesses
        // (e.g. git-diff helpers shipped with git itself) resolve.
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("GIT_DIR", git_dir)
        .env("GIT_WORK_TREE", worktree)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        // Phase E: keep the same LFS/transport hardening on the collection path
        // (env_clear already dropped ambient GIT_*), so a hostile worktree can
        // never trigger an LFS smudge or a non-file transport during diff capture.
        .env("GIT_LFS_SKIP_SMUDGE", "1")
        .env("GIT_ALLOW_PROTOCOL", "http:https:file")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn()?;
    let mut stdout_pipe = child.stdout.take().expect("stdout piped");
    let mut stderr_pipe = child.stderr.take().expect("stderr piped");

    // Reader threads keep the pipes drained (a full pipe would deadlock the
    // child); the main thread owns the deadline and the kill.
    let out_reader = std::thread::spawn(move || {
        let mut kept: Vec<u8> = Vec::new();
        let mut truncated = false;
        let mut buf = [0u8; 64 * 1024];
        loop {
            match stdout_pipe.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if kept.len() < max_out {
                        let take = n.min(max_out - kept.len());
                        kept.extend_from_slice(&buf[..take]);
                        if take < n {
                            truncated = true;
                        }
                    } else {
                        truncated = true;
                    }
                }
                Err(_) => break,
            }
        }
        (kept, truncated)
    });
    let err_reader = std::thread::spawn(move || {
        let mut kept: Vec<u8> = Vec::new();
        let mut buf = [0u8; 8 * 1024];
        loop {
            match stderr_pipe.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if kept.len() < 4096 {
                        let take = n.min(4096 - kept.len());
                        kept.extend_from_slice(&buf[..take]);
                    }
                }
                Err(_) => break,
            }
        }
        String::from_utf8_lossy(&kept).into_owned()
    });

    let started = Instant::now();
    let mut timed_out = false;
    let status = loop {
        match child.try_wait()? {
            Some(st) => break Some(st),
            None => {
                if started.elapsed() > timeout {
                    timed_out = true;
                    child.kill().ok();
                    break child.wait().ok();
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    };

    let (stdout, stdout_truncated) = out_reader.join().unwrap_or_default();
    let stderr_head = err_reader.join().unwrap_or_default();
    Ok(BoundedOutput {
        status: status.and_then(|s| s.code()),
        timed_out,
        stdout,
        stdout_truncated,
        stderr_head,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::materialize_local;
    use uuid::Uuid;

    fn fixture() -> (std::path::PathBuf, crate::MaterializedWorkspace) {
        let tmp = std::env::temp_dir().join(format!("fbx-collect-test-{}", Uuid::now_v7()));
        let src = tmp.join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("a.txt"), "hello\n").unwrap();
        let ws = materialize_local(&tmp.join("data"), Uuid::now_v7(), &src).unwrap();
        (tmp, ws)
    }

    fn root_of(ws: &crate::MaterializedWorkspace) -> &Path {
        ws.host_dir.parent().unwrap()
    }

    #[test]
    fn clean_worktree_yields_empty_diff_not_missing() {
        let (tmp, ws) = fixture();
        match collect_diff(
            root_of(&ws),
            ws.base_commit.as_deref(),
            &DiffCaps::default(),
        ) {
            CollectionOutcome::Diff(d) => {
                assert!(d.patch.is_empty(), "expected empty diff, got: {}", d.patch);
                assert!(!d.truncated);
            }
            CollectionOutcome::Missing { reason } => panic!("unexpected missing: {reason}"),
        }
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn hostile_git_config_is_never_executed() {
        let (tmp, ws) = fixture();
        let marker = tmp.join("pwned-by-diff-external");
        // The "agent" poisons ITS copy of .git and .gitattributes with every
        // classic config-driven execution vector…
        std::fs::write(ws.host_dir.join("a.txt"), "changed\n").unwrap();
        std::fs::write(
            ws.host_dir.join(".git/config"),
            format!(
                "[user]\n\temail = t@t\n\tname = t\n[diff]\n\texternal = touch {}\n[core]\n\tfsmonitor = touch {}\n\thooksPath = /tmp\n[filter \"evil\"]\n\tclean = touch {}\n\trequired = true\n",
                marker.display(),
                marker.display(),
                marker.display()
            ),
        )
        .unwrap();
        std::fs::write(ws.host_dir.join(".gitattributes"), "* filter=evil\n").unwrap();
        let hook = ws.host_dir.join(".git/hooks/pre-auto-gc");
        std::fs::create_dir_all(hook.parent().unwrap()).unwrap();
        std::fs::write(&hook, format!("#!/bin/sh\ntouch {}\n", marker.display())).unwrap();

        // …and collection still produces the true diff without running any of it.
        match collect_diff(
            root_of(&ws),
            ws.base_commit.as_deref(),
            &DiffCaps::default(),
        ) {
            CollectionOutcome::Diff(d) => {
                assert!(
                    d.patch.contains("changed"),
                    "diff lost the edit: {}",
                    d.patch
                );
                // .gitattributes is a real (hostile but inert) file change —
                // it may appear in the diff; the marker must not exist.
            }
            CollectionOutcome::Missing { reason } => panic!("unexpected missing: {reason}"),
        }
        assert!(
            !marker.exists(),
            "agent-controlled git config was EXECUTED during collection"
        );
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn oversized_diff_is_truncated_and_flagged() {
        let (tmp, ws) = fixture();
        let big = "x".repeat(64 * 1024);
        std::fs::write(ws.host_dir.join("big.txt"), &big).unwrap();
        let caps = DiffCaps {
            max_bytes: 4 * 1024,
            git_timeout: Duration::from_secs(30),
        };
        match collect_diff(root_of(&ws), ws.base_commit.as_deref(), &caps) {
            CollectionOutcome::Diff(d) => {
                assert!(d.truncated, "expected truncation flag");
                assert!(d.bytes <= 4 * 1024);
                assert!(d.sha256.starts_with("sha256:"));
            }
            CollectionOutcome::Missing { reason } => panic!("unexpected missing: {reason}"),
        }
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn missing_baseline_is_explicit_not_no_changes() {
        let (tmp, ws) = fixture();
        std::fs::remove_dir_all(root_of(&ws).join(BASELINE_DIR)).unwrap();
        match collect_diff(
            root_of(&ws),
            ws.base_commit.as_deref(),
            &DiffCaps::default(),
        ) {
            CollectionOutcome::Missing { reason } => {
                assert!(reason.contains("baseline"), "reason: {reason}");
            }
            CollectionOutcome::Diff(_) => panic!("must not diff without the pristine baseline"),
        }
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn missing_worktree_is_explicit() {
        let (tmp, ws) = fixture();
        let root = root_of(&ws).to_path_buf();
        std::fs::remove_dir_all(&ws.host_dir).unwrap();
        match collect_diff(&root, ws.base_commit.as_deref(), &DiffCaps::default()) {
            CollectionOutcome::Missing { reason } => {
                assert!(reason.contains("worktree"), "reason: {reason}");
            }
            CollectionOutcome::Diff(_) => panic!("must not report a diff with no worktree"),
        }
        std::fs::remove_dir_all(&tmp).ok();
    }

    /// M2: the integrity header (`bytes`/`sha256`) must describe the EXACT
    /// stored artifact bytes — the lossy-UTF-8 patch that gets written — not
    /// the raw git stdout. Otherwise the collector's `stream` consumer, which
    /// verifies the received body against this header, would reject every diff
    /// whose git output contained invalid UTF-8. A new tracked text file with
    /// invalid UTF-8 (no NUL → git treats it as text and emits the raw bytes)
    /// forces the raw/stored divergence.
    #[test]
    fn diff_integrity_describes_stored_bytes_not_raw() {
        let (tmp, ws) = fixture();
        std::fs::write(ws.host_dir.join("bad.txt"), [0xff, 0xfe, b'\n']).unwrap();
        match collect_diff(
            root_of(&ws),
            ws.base_commit.as_deref(),
            &DiffCaps::default(),
        ) {
            CollectionOutcome::Diff(d) => {
                assert!(
                    d.patch.contains('\u{FFFD}'),
                    "precondition: lossy replacement must have occurred; patch: {:?}",
                    d.patch
                );
                assert_eq!(
                    d.bytes,
                    d.patch.len() as u64,
                    "bytes must describe the stored patch, not raw git stdout"
                );
                use sha2::{Digest, Sha256};
                let want = format!("sha256:{}", hex::encode(Sha256::digest(d.patch.as_bytes())));
                assert_eq!(d.sha256, want, "sha256 must be over the stored patch bytes");
            }
            CollectionOutcome::Missing { reason } => panic!("unexpected missing: {reason}"),
        }
        std::fs::remove_dir_all(&tmp).ok();
    }

    /// H4 (archive transport + collection halves): an in-tree symlink present
    /// in the worktree survives pack→unpack (the control-plane→pod archive
    /// transport) AND appears in the collected diff (git mode 120000), matching
    /// Docker. The `cmd_init`→`copy_tree`→/workspace half is covered by
    /// `workspaced`'s `copy_tree_preserves_intree_symlink_and_drops_escaping`.
    #[cfg(unix)]
    #[test]
    fn symlink_survives_pack_unpack_and_appears_in_diff() {
        let (tmp, ws) = fixture();
        // A tracked in-tree relative symlink in the worktree.
        std::os::unix::fs::symlink("a.txt", ws.host_dir.join("link")).unwrap();

        // Pack the session root (repo/ + baseline-git/) and unpack it into a
        // fresh "pod" dir — exactly the control-plane→pod workspace transport.
        let packed = crate::pack_workspace(root_of(&ws)).unwrap();
        let pod = tmp.join("pod");
        crate::unpack_archive(&packed.bytes, &pod, 100 * 1024 * 1024).unwrap();
        assert!(
            std::fs::symlink_metadata(pod.join("repo/link"))
                .unwrap()
                .file_type()
                .is_symlink(),
            "symlink must survive the archive transport as a real symlink"
        );

        // Collection against the reconstructed tree sees the new symlink
        // (git records symlinks as mode 120000) — not a crash, not a loss.
        match collect_diff(&pod, ws.base_commit.as_deref(), &DiffCaps::default()) {
            CollectionOutcome::Diff(d) => {
                assert!(
                    d.patch.contains("link"),
                    "diff lost the symlink: {}",
                    d.patch
                );
                assert!(
                    d.patch.contains("120000"),
                    "symlink not recorded as a symlink: {}",
                    d.patch
                );
            }
            CollectionOutcome::Missing { reason } => panic!("unexpected missing: {reason}"),
        }
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn deleted_and_added_files_appear() {
        let (tmp, ws) = fixture();
        std::fs::remove_file(ws.host_dir.join("a.txt")).unwrap();
        std::fs::write(ws.host_dir.join("b.txt"), "new file\n").unwrap();
        match collect_diff(
            root_of(&ws),
            ws.base_commit.as_deref(),
            &DiffCaps::default(),
        ) {
            CollectionOutcome::Diff(d) => {
                assert!(d.patch.contains("deleted file"), "{}", d.patch);
                assert!(d.patch.contains("b.txt"), "{}", d.patch);
            }
            CollectionOutcome::Missing { reason } => panic!("unexpected missing: {reason}"),
        }
        std::fs::remove_dir_all(&tmp).ok();
    }
}
