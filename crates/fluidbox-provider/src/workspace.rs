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
    #[error("invalid workspace input: {0}")]
    Invalid(String),
}

/// Build/tooling junk kept out of base commits and captured diffs, via git's
/// LOCAL exclude (never written into the repo the agent sees).
const LOCAL_EXCLUDES: &str = "__pycache__/\n*.pyc\n*.pyo\n.pytest_cache/\nnode_modules/\n.DS_Store\n*.class\ntarget/\n.venv/\nvenv/\n*.egg-info/\n";

fn run_git(dir: &Path, args: &[&str]) -> Result<String, WorkspaceError> {
    run_git_env(dir, args, &[])
}

/// `envs` is how credentials reach git: via GIT_CONFIG_* variables, never on
/// the command line (visible in `ps`) and never in on-disk config (the .git
/// dir is mounted into the sandbox). Error text includes args, never envs.
fn run_git_env(
    dir: &Path,
    args: &[&str],
    envs: &[(String, String)],
) -> Result<String, WorkspaceError> {
    let mut cmd = Command::new("git");
    cmd.current_dir(dir).args(args);
    // Never fall back to interactive credential prompts.
    cmd.env("GIT_TERMINAL_PROMPT", "0");
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let out = cmd.output()?;
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
    let dest = data_dir
        .join("workspaces")
        .join(session.to_string())
        .join("repo");
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

    let _ = std::fs::write(dest.join(".git/info/exclude"), LOCAL_EXCLUDES);

    run_git(&dest, &["add", "-A"])?;
    // Commit may be empty if nothing to add; allow it.
    let _ = run_git(
        &dest,
        &["commit", "-q", "--allow-empty", "-m", "fluidbox base"],
    );
    let base_commit = run_git(&dest, &["rev-parse", "HEAD"]).ok();

    Ok(MaterializedWorkspace {
        file_count: count_files(&dest),
        host_dir: dest,
        base_commit,
    })
}

fn session_workspace_root(data_dir: &Path, session: Uuid) -> PathBuf {
    data_dir.join("workspaces").join(session.to_string())
}

fn validate_clone_url(url: &str) -> Result<(), WorkspaceError> {
    // Scheme allowlist doubles as argument-injection protection (a "URL"
    // starting with `-` would otherwise be parsed as a git option).
    let ok = ["https://", "http://", "file://"]
        .iter()
        .any(|s| url.starts_with(s));
    if !ok {
        return Err(WorkspaceError::Invalid(format!(
            "clone_url must be http(s):// or file:// (got '{}')",
            url.chars().take(40).collect::<String>()
        )));
    }
    Ok(())
}

fn validate_ref(r: &str) -> Result<(), WorkspaceError> {
    let bad = r.is_empty()
        || r.starts_with('-')
        || r.starts_with('.')
        || r.contains("..")
        || r.contains(':')
        || r.chars().any(|c| c.is_whitespace() || c.is_control());
    if bad {
        return Err(WorkspaceError::Invalid(format!("invalid git ref '{r}'")));
    }
    Ok(())
}

fn validate_commit_sha(sha: &str) -> Result<(), WorkspaceError> {
    if sha.len() < 7 || sha.len() > 40 || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(WorkspaceError::Invalid(format!(
            "invalid commit sha '{sha}'"
        )));
    }
    Ok(())
}

/// Materialize an exact ref/commit of a remote repository into an isolated
/// per-session workspace. This is the control-plane side of design §5.2: the
/// credential (an opaque `Authorization` header value) is used for the fetch
/// only — it is never written to disk, never in argv, and the origin remote
/// is removed afterwards so nothing credential-shaped reaches the sandbox.
pub fn materialize_git(
    data_dir: &Path,
    session: Uuid,
    clone_url: &str,
    reference: Option<&str>,
    commit_sha: Option<&str>,
    auth_header: Option<&str>,
) -> Result<MaterializedWorkspace, WorkspaceError> {
    validate_clone_url(clone_url)?;
    if let Some(r) = reference {
        validate_ref(r)?;
    }
    if let Some(sha) = commit_sha {
        validate_commit_sha(sha)?;
    }

    let root = session_workspace_root(data_dir, session);
    let dest = root.join("repo");
    // Idempotent retry: a partial previous attempt is discarded wholesale.
    if root.exists() {
        std::fs::remove_dir_all(&root)?;
    }
    std::fs::create_dir_all(&dest)?;

    let result = fetch_and_checkout(&dest, clone_url, reference, commit_sha, auth_header);
    if result.is_err() {
        // A failed clone must not leave a half-materialized workspace behind.
        std::fs::remove_dir_all(&root).ok();
    }
    result
}

fn fetch_and_checkout(
    dest: &Path,
    clone_url: &str,
    reference: Option<&str>,
    commit_sha: Option<&str>,
    auth_header: Option<&str>,
) -> Result<MaterializedWorkspace, WorkspaceError> {
    let auth_env: Vec<(String, String)> = match auth_header {
        Some(h) => vec![
            ("GIT_CONFIG_COUNT".into(), "1".into()),
            ("GIT_CONFIG_KEY_0".into(), "http.extraheader".into()),
            ("GIT_CONFIG_VALUE_0".into(), format!("Authorization: {h}")),
        ],
        None => vec![],
    };

    run_git(dest, &["init", "-q"])?;
    run_git(dest, &["remote", "add", "origin", clone_url])?;

    match commit_sha {
        Some(sha) => {
            // Exact-commit checkout (e.g. a PR head, immune to branch moves).
            // GitHub serves arbitrary SHAs shallow; generic servers may not,
            // so fall back to a full branch fetch and resolve the SHA there.
            let shallow = run_git_env(
                dest,
                &["fetch", "-q", "--depth", "1", "origin", sha],
                &auth_env,
            );
            if shallow.is_err() {
                run_git_env(
                    dest,
                    &[
                        "fetch",
                        "-q",
                        "origin",
                        "+refs/heads/*:refs/remotes/origin/*",
                    ],
                    &auth_env,
                )?;
            }
            let commit = format!("{sha}^{{commit}}");
            run_git(dest, &["rev-parse", "--verify", "--quiet", &commit]).map_err(|_| {
                WorkspaceError::Git(format!("commit {sha} not found in {clone_url}"))
            })?;
            run_git(dest, &["checkout", "-q", "-B", "fluidbox-work", sha])?;
        }
        None => {
            // Exact ref (branch/tag) or the remote HEAD when unspecified.
            let target = reference.unwrap_or("HEAD");
            run_git_env(
                dest,
                &["fetch", "-q", "--depth", "1", "origin", target],
                &auth_env,
            )?;
            let branch = reference.unwrap_or("fluidbox-work");
            run_git(dest, &["checkout", "-q", "-B", branch, "FETCH_HEAD"])?;
        }
    }

    // Belt and braces: the sandbox copy keeps its history but loses the
    // remote — remote mutations go through governed capabilities, not `git
    // push` from inside the sandbox.
    run_git(dest, &["remote", "remove", "origin"])?;
    run_git(dest, &["config", "user.email", "runner@fluidbox.local"])?;
    run_git(dest, &["config", "user.name", "fluidbox"])?;
    let _ = std::fs::write(dest.join(".git/info/exclude"), LOCAL_EXCLUDES);

    let base_commit = run_git(dest, &["rev-parse", "HEAD"]).ok();
    Ok(MaterializedWorkspace {
        file_count: count_files(dest),
        host_dir: dest.to_path_buf(),
        base_commit,
    })
}

/// Remove a session's workspace directory. Idempotent: missing dir is fine.
/// Only ever touches `<data_dir>/workspaces/<session>` by construction.
pub fn cleanup_workspace(data_dir: &Path, session: Uuid) -> Result<(), WorkspaceError> {
    let root = session_workspace_root(data_dir, session);
    match std::fs::remove_dir_all(&root) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
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

    /// A local source repo with two commits on `main` and a `feature` branch,
    /// served over file:// — the full clone path without any network.
    fn git_fixture(tmp: &Path) -> (String, String, String) {
        let src = tmp.join("origin");
        std::fs::create_dir_all(&src).unwrap();
        let git = |args: &[&str]| run_git(&src, args).unwrap();
        git(&["init", "-q", "-b", "main"]);
        git(&["config", "user.email", "t@t"]);
        git(&["config", "user.name", "t"]);
        std::fs::write(src.join("a.txt"), "one\n").unwrap();
        git(&["add", "-A"]);
        git(&["commit", "-q", "-m", "c1"]);
        let first = git(&["rev-parse", "HEAD"]);
        std::fs::write(src.join("a.txt"), "two\n").unwrap();
        git(&["add", "-A"]);
        git(&["commit", "-q", "-m", "c2"]);
        let head = git(&["rev-parse", "HEAD"]);
        git(&["branch", "feature", &first]);
        (format!("file://{}", src.display()), first, head)
    }

    #[test]
    fn materialize_git_default_head() {
        let tmp = std::env::temp_dir().join(format!("fbx-git-test-{}", Uuid::now_v7()));
        let (url, _first, head) = git_fixture(&tmp);
        let data = tmp.join("data");
        let session = Uuid::now_v7();

        let ws = materialize_git(&data, session, &url, None, None, None).unwrap();
        assert_eq!(ws.base_commit.as_deref(), Some(head.as_str()));
        assert_eq!(
            std::fs::read_to_string(ws.host_dir.join("a.txt")).unwrap(),
            "two\n"
        );
        // The sandbox copy has no remote to push to.
        assert_eq!(run_git(&ws.host_dir, &["remote"]).unwrap(), "");

        // Diff capture works over the real cloned history.
        std::fs::write(ws.host_dir.join("a.txt"), "three\n").unwrap();
        let diff = capture_diff(&ws.host_dir, ws.base_commit.as_deref()).unwrap();
        assert!(diff.contains("three"));

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn materialize_git_exact_ref_and_exact_commit() {
        let tmp = std::env::temp_dir().join(format!("fbx-git-test-{}", Uuid::now_v7()));
        let (url, first, head) = git_fixture(&tmp);
        let data = tmp.join("data");

        // Branch ref → that branch's head, not the default branch.
        let by_ref =
            materialize_git(&data, Uuid::now_v7(), &url, Some("feature"), None, None).unwrap();
        assert_eq!(by_ref.base_commit.as_deref(), Some(first.as_str()));
        assert_eq!(
            std::fs::read_to_string(by_ref.host_dir.join("a.txt")).unwrap(),
            "one\n"
        );

        // Exact commit → exactly that commit, immune to branch movement
        // (file:// doesn't serve arbitrary SHAs shallow — exercises the
        // full-fetch fallback).
        let by_sha =
            materialize_git(&data, Uuid::now_v7(), &url, None, Some(&first), None).unwrap();
        assert_eq!(by_sha.base_commit.as_deref(), Some(first.as_str()));
        assert_eq!(
            std::fs::read_to_string(by_sha.host_dir.join("a.txt")).unwrap(),
            "one\n"
        );
        // ref+sha together: sha wins (it's the more exact pin).
        let both =
            materialize_git(&data, Uuid::now_v7(), &url, Some("main"), Some(&head), None).unwrap();
        assert_eq!(both.base_commit.as_deref(), Some(head.as_str()));

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn materialize_git_failure_leaves_nothing_behind() {
        let tmp = std::env::temp_dir().join(format!("fbx-git-test-{}", Uuid::now_v7()));
        let data = tmp.join("data");
        let session = Uuid::now_v7();

        let missing = tmp.join("no-such-repo");
        let err = materialize_git(
            &data,
            session,
            &format!("file://{}", missing.display()),
            None,
            None,
            None,
        );
        assert!(err.is_err());
        assert!(
            !data.join("workspaces").join(session.to_string()).exists(),
            "failed clone must not leave a partial workspace"
        );

        // Bad commit in a good repo also cleans up.
        let (url, ..) = git_fixture(&tmp);
        let err = materialize_git(&data, session, &url, None, Some("deadbeefdeadbeef"), None);
        assert!(err.is_err());
        assert!(!data.join("workspaces").join(session.to_string()).exists());

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn materialize_git_rejects_hostile_inputs() {
        let tmp = std::env::temp_dir().join(format!("fbx-git-test-{}", Uuid::now_v7()));
        let data = tmp.join("data");
        let sid = Uuid::now_v7();
        // Option-shaped "URL" (argument injection) and bad schemes.
        for url in ["--upload-pack=evil", "ssh://h/r.git", "git@github.com:o/r"] {
            assert!(matches!(
                materialize_git(&data, sid, url, None, None, None),
                Err(WorkspaceError::Invalid(_))
            ));
        }
        // Option-shaped / malformed refs and shas.
        for r in ["-evil", "a b", "a..b", "x:y"] {
            assert!(matches!(
                materialize_git(
                    &data,
                    sid,
                    "https://github.com/o/r.git",
                    Some(r),
                    None,
                    None
                ),
                Err(WorkspaceError::Invalid(_))
            ));
        }
        for sha in ["xyz", "abc", "-deadbeef"] {
            assert!(matches!(
                materialize_git(
                    &data,
                    sid,
                    "https://github.com/o/r.git",
                    None,
                    Some(sha),
                    None
                ),
                Err(WorkspaceError::Invalid(_))
            ));
        }
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn cleanup_workspace_is_idempotent() {
        let tmp = std::env::temp_dir().join(format!("fbx-git-test-{}", Uuid::now_v7()));
        let (url, ..) = git_fixture(&tmp);
        let data = tmp.join("data");
        let session = Uuid::now_v7();
        materialize_git(&data, session, &url, None, None, None).unwrap();
        assert!(data.join("workspaces").join(session.to_string()).exists());
        cleanup_workspace(&data, session).unwrap();
        assert!(!data.join("workspaces").join(session.to_string()).exists());
        // Second call: nothing to do, still Ok.
        cleanup_workspace(&data, session).unwrap();
        std::fs::remove_dir_all(&tmp).ok();
    }

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
