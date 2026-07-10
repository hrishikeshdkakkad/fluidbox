//! Control-plane-side workspace materialization and diff capture.
//!
//! This runs during the session's `initializing` phase, BEFORE the agent
//! starts. The credentialed fetch (git URL) never happens inside the
//! sandbox — the agent only ever sees a copy bind-mounted at /workspace.

use std::path::{Path, PathBuf};
use std::process::Command;
use uuid::Uuid;

pub struct MaterializedWorkspace {
    pub host_dir: PathBuf,
    pub base_commit: Option<String>,
    pub file_count: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum WorkspaceError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("git command failed: {0}")]
    Git(String),
    #[error("source path does not exist: {0}")]
    NoSource(String),
}

fn run_git(dir: &Path, args: &[&str]) -> Result<String, WorkspaceError> {
    let out = Command::new("git").current_dir(dir).args(args).output()?;
    if !out.status.success() {
        return Err(WorkspaceError::Git(format!(
            "git {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn count_files(dir: &Path) -> u64 {
    fn walk(dir: &Path, n: &mut u64) {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for e in entries.flatten() {
                let p = e.path();
                if p.file_name().map(|f| f == ".git").unwrap_or(false) {
                    continue;
                }
                if p.is_dir() {
                    walk(&p, n);
                } else {
                    *n += 1;
                }
            }
        }
    }
    let mut n = 0;
    walk(dir, &mut n);
    n
}

/// Materialize a local directory into an isolated per-session workspace.
/// Uses a git-tracked copy so we can diff at the end; the original tree is
/// never touched.
pub fn materialize_local(
    data_dir: &Path,
    session: Uuid,
    source: &Path,
) -> Result<MaterializedWorkspace, WorkspaceError> {
    if !source.exists() {
        return Err(WorkspaceError::NoSource(source.display().to_string()));
    }
    let dest = data_dir.join("workspaces").join(session.to_string()).join("repo");
    std::fs::create_dir_all(&dest)?;

    // Copy contents (excluding any existing .git so we control history).
    copy_tree(source, &dest)?;

    // Ensure a git repo + a base commit to diff against. If the source was
    // already a git repo we snapshot its current state as our base.
    // Always start a fresh git history in the copy so our base commit is
    // meaningful and the source repo's objects don't bloat the diff. `copy_tree`
    // already skipped any incoming .git, but a nested one is possible — remove it.
    if dest.join(".git").exists() {
        std::fs::remove_dir_all(dest.join(".git")).ok();
    }
    run_git(&dest, &["init", "-q"])?;
    run_git(&dest, &["config", "user.email", "runner@fluidbox.local"])?;
    run_git(&dest, &["config", "user.name", "fluidbox"])?;

    // Keep build/tooling junk out of the base commit and the captured diff,
    // via git's LOCAL exclude (never written into the repo the agent sees).
    let _ = std::fs::write(
        dest.join(".git/info/exclude"),
        "__pycache__/\n*.pyc\n*.pyo\n.pytest_cache/\nnode_modules/\n.DS_Store\n*.class\ntarget/\n.venv/\nvenv/\n*.egg-info/\n",
    );

    run_git(&dest, &["add", "-A"])?;
    // Commit may be empty if nothing to add; allow it.
    let _ = run_git(&dest, &["commit", "-q", "--allow-empty", "-m", "fluidbox base"]);
    let base_commit = run_git(&dest, &["rev-parse", "HEAD"]).ok();

    Ok(MaterializedWorkspace {
        file_count: count_files(&dest),
        host_dir: dest,
        base_commit,
    })
}

/// Capture the agent's changes as a binary-safe unified diff artifact.
pub fn capture_diff(host_dir: &Path, base_commit: Option<&str>) -> Result<String, WorkspaceError> {
    // Stage everything the agent produced, then diff against the base.
    run_git(host_dir, &["add", "-A"])?;
    let base = base_commit.unwrap_or("HEAD");
    // Use --binary so the diff can be applied; --no-color for a clean artifact.
    let diff = run_git(host_dir, &["diff", "--binary", "--no-color", base])?;
    if !diff.is_empty() {
        return Ok(diff);
    }
    // Fall back to a cached diff (in case the agent already committed).
    run_git(host_dir, &["diff", "--binary", "--no-color", base, "HEAD"])
}

fn copy_tree(src: &Path, dst: &Path) -> Result<(), WorkspaceError> {
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let name = entry.file_name();
        if name == ".git" {
            continue;
        }
        let from = entry.path();
        let to = dst.join(&name);
        if from.is_dir() {
            std::fs::create_dir_all(&to)?;
            copy_tree(&from, &to)?;
        } else {
            std::fs::copy(&from, &to)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn materialize_and_diff_roundtrip() {
        let tmp = std::env::temp_dir().join(format!("fbx-ws-test-{}", Uuid::now_v7()));
        let src = tmp.join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("a.txt"), "hello\n").unwrap();

        let data = tmp.join("data");
        let session = Uuid::now_v7();
        let ws = materialize_local(&data, session, &src).unwrap();
        assert!(ws.base_commit.is_some());
        assert_eq!(ws.file_count, 1);

        // Simulate the agent editing a file.
        std::fs::write(ws.host_dir.join("a.txt"), "hello world\n").unwrap();
        std::fs::write(ws.host_dir.join("b.txt"), "new\n").unwrap();

        let diff = capture_diff(&ws.host_dir, ws.base_commit.as_deref()).unwrap();
        assert!(diff.contains("a.txt"));
        assert!(diff.contains("b.txt"));
        assert!(diff.contains("hello world"));

        std::fs::remove_dir_all(&tmp).ok();
    }
}
