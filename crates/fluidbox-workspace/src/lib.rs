//! fluidbox-workspace — the workspace lifecycle both execution providers
//! share: control-plane-side materialization, the pristine `.git` baseline,
//! and hardened terminal diff collection.
//!
//! Materialization runs during the session's `initializing` phase, BEFORE
//! the agent starts. The credentialed fetch (git URL) never happens inside
//! the sandbox — the agent only ever sees a copy of the tree.
//!
//! Collection (see [`collect`]) NEVER executes git against agent-controlled
//! `.git` state, on any provider: it reconstructs a throwaway repository
//! from the pristine baseline saved here at materialization time.
//!
//! This crate deliberately has no bollard/kube dependencies (it is shared
//! by every provider), and `fluidbox-core` stays I/O-free (git subprocess
//! I/O lives here — settled Q13 of the 2026-07-15 design).

use fluidbox_core::netpolicy::{ip_blocked, IpCidr};
use std::net::{IpAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::Command;
use uuid::Uuid;

pub mod archive;
pub mod collect;

/// The clone-URL egress policy (Phase E, E4), built server-side from the shared
/// `EgressPolicy` and passed into materialization. The git fetch runs
/// out-of-process, so the reqwest SSRF resolver cannot cover it; instead we
/// resolve the http(s) host and validate EVERY resolved address with the SAME
/// `fluidbox_core::netpolicy` predicate the in-process clients use, pin git away
/// from redirects, and (optionally) route it through the egress proxy.
///
/// TOCTOU residual DISCLOSED: git re-resolves the host independently at fetch
/// time, so a DNS-rebinding name could differ between this check and git's dial;
/// closing it fully needs an egress proxy or network-layer egress control.
#[derive(Debug, Clone, Default)]
pub struct GitEgressPolicy {
    pub dev_loopback: bool,
    pub allow_cidrs: Vec<IpCidr>,
    /// The configured `FLUIDBOX_GITHUB_CLONE_BASE`; a `file://` clone URL is
    /// allowed only when it starts with this prefix (or under the dev seam).
    pub clone_base_file_prefix: Option<String>,
    /// `FLUIDBOX_EGRESS_PROXY`, exported to the git fetch subprocess as
    /// HTTPS_PROXY/https_proxy when present.
    pub proxy: Option<String>,
}

pub use archive::{
    clear_dir_contents, pack_workspace, pack_workspace_to_file, unpack_archive,
    unpack_archive_reader, verify_archive, PackedArchive, StoredArchive,
};
pub use collect::{collect_diff, collect_diff_at, CollectedDiff, CollectionOutcome, DiffCaps};

/// Directory (under the per-session workspace root) holding the pristine
/// copy of the materialized `.git` — saved before the agent ever runs,
/// never mounted into the sandbox, and the ONLY `.git` state collection
/// will execute against.
pub const BASELINE_DIR: &str = "baseline-git";

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

/// The Phase-E transport-hardening env applied on EVERY git invocation, on BOTH
/// the materialize path (`run_git_env`, this file) and the diff-collection path
/// (`collect::run_git_scrubbed`): never smudge-fetch LFS objects from an
/// arbitrary `lfs.url`, and restrict git transports to the three schemes we
/// validate (no ext::/dumb/ssh helpers, incl. on redirect). SINGLE-SOURCED here
/// so a deletion breaks both real builders AND the tests that assert them —
/// there is deliberately no parallel constant to drift against.
pub(crate) fn transport_hardening_env() -> [(&'static str, &'static str); 2] {
    [
        ("GIT_LFS_SKIP_SMUDGE", "1"),
        ("GIT_ALLOW_PROTOCOL", "http:https:file"),
    ]
}

/// Build a smart-HTTP fetch argv with the mandatory SSRF guard prefix
/// `-c http.followRedirects=false` — the out-of-process analogue of the reqwest
/// `Policy::none` the in-process clients use: a fetch must not follow a 3xx onto
/// an unvalidated (internal) host. EVERY network fetch is built through this one
/// helper (via `run_fetch`) so the flag is single-sourced and a test asserting
/// this fn's output breaks the moment the prefix is dropped from the real path.
fn fetch_argv(tail: &[&str]) -> Vec<String> {
    ["-c", "http.followRedirects=false"]
        .iter()
        .chain(tail.iter())
        .map(|s| s.to_string())
        .collect()
}

/// Run one git fetch: the argv is built through `fetch_argv` (redirect guard) and
/// the credential/proxy env is threaded as usual.
fn run_fetch(
    dir: &Path,
    tail: &[&str],
    envs: &[(String, String)],
) -> Result<String, WorkspaceError> {
    let argv = fetch_argv(tail);
    let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
    run_git_env(dir, &refs, envs)
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
    // Phase E hardening on EVERY git invocation (LFS smudge off + transport
    // allowlist), single-sourced so tests assert exactly what the real path sets.
    for (k, v) in transport_hardening_env() {
        cmd.env(k, v);
    }
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

pub fn session_workspace_root(data_dir: &Path, session: Uuid) -> PathBuf {
    data_dir.join("workspaces").join(session.to_string())
}

/// Save the pristine baseline: a full copy of the just-materialized `.git`,
/// beside the workspace (outside anything a sandbox ever sees). Collection
/// reconstructs its throwaway repo from THIS, so agent mutations to the
/// workspace's own `.git` (config, hooks, attributes) are never executed.
fn save_pristine_baseline(repo: &Path) -> Result<(), WorkspaceError> {
    let root = repo
        .parent()
        .ok_or_else(|| WorkspaceError::Invalid("workspace repo has no parent".into()))?;
    let baseline = root.join(BASELINE_DIR);
    if baseline.exists() {
        std::fs::remove_dir_all(&baseline)?;
    }
    copy_dir_all(&repo.join(".git"), &baseline)?;
    Ok(())
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
    let dest = session_workspace_root(data_dir, session).join("repo");
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

    save_pristine_baseline(&dest)?;

    Ok(MaterializedWorkspace {
        file_count: count_files(&dest),
        host_dir: dest,
        base_commit,
    })
}

fn validate_clone_url(url: &str, egress: &GitEgressPolicy) -> Result<(), WorkspaceError> {
    // Scheme allowlist doubles as argument-injection protection (a "URL"
    // starting with `-` would otherwise be parsed as a git option).
    if url.starts_with("https://") {
        resolve_and_validate_host(url, egress)
    } else if url.starts_with("http://") {
        // Plain http only under the dev-loopback seam (the e2e loopback fakes).
        if !egress.dev_loopback {
            return Err(WorkspaceError::Invalid(
                "refusing a plain-http clone URL (dev-loopback only)".into(),
            ));
        }
        resolve_and_validate_host(url, egress)
    } else if url.starts_with("file://") {
        // file:// only under the configured clone base prefix (or the dev seam).
        let allowed = egress.dev_loopback
            || egress
                .clone_base_file_prefix
                .as_deref()
                .map(|p| url.starts_with(p))
                .unwrap_or(false);
        if !allowed {
            return Err(WorkspaceError::Invalid(
                "refusing a file:// clone URL outside the configured clone base".into(),
            ));
        }
        Ok(())
    } else {
        Err(WorkspaceError::Invalid(format!(
            "clone_url must be http(s):// or file:// (got '{}')",
            url.chars().take(40).collect::<String>()
        )))
    }
}

/// Extract (host, port) from an http(s) URL without a URL-parser dependency:
/// strip the scheme, take the authority up to the first `/?#`, drop any
/// userinfo, and split an optional port (bracketed for IPv6 literals). The port
/// only feeds DNS resolution (port-independent), so a missing one defaults to 443.
fn host_and_port(url: &str) -> Option<(String, u16)> {
    let after = url.split_once("://")?.1;
    let authority = after.split(['/', '?', '#']).next()?;
    let hostport = authority
        .rsplit_once('@')
        .map(|(_, hp)| hp)
        .unwrap_or(authority);
    if let Some(rest) = hostport.strip_prefix('[') {
        let (h, tail) = rest.split_once(']')?;
        let port = tail
            .strip_prefix(':')
            .and_then(|p| p.parse().ok())
            .unwrap_or(443);
        return Some((h.to_string(), port));
    }
    match hostport.rsplit_once(':') {
        Some((h, p)) => Some((h.to_string(), p.parse().ok()?)),
        None => Some((hostport.to_string(), 443)),
    }
}

/// Resolve an http(s) clone URL's host and refuse if it is — or resolves to — a
/// private/loopback/link-local/metadata address (loopback allowed only under the
/// dev seam). A bare IP literal is checked directly (no DNS). The shared
/// `fluidbox_core::netpolicy` predicate keeps this in lockstep with the reqwest
/// clients. TOCTOU residual disclosed on `GitEgressPolicy`.
fn resolve_and_validate_host(url: &str, egress: &GitEgressPolicy) -> Result<(), WorkspaceError> {
    let (host, port) = host_and_port(url)
        .ok_or_else(|| WorkspaceError::Invalid("clone_url has no host".into()))?;
    if let Ok(ip) = host.trim_matches(['[', ']']).parse::<IpAddr>() {
        if ip_blocked(ip, egress.dev_loopback, &egress.allow_cidrs) {
            return Err(WorkspaceError::Invalid(
                "refusing a clone URL at a private/loopback/link-local address".into(),
            ));
        }
        return Ok(());
    }
    let addrs: Vec<IpAddr> = (host.as_str(), port)
        .to_socket_addrs()
        .map_err(|_| WorkspaceError::Invalid("clone_url host did not resolve".into()))?
        .map(|s| s.ip())
        .collect();
    if addrs.is_empty() {
        return Err(WorkspaceError::Invalid(
            "clone_url host did not resolve".into(),
        ));
    }
    if addrs
        .iter()
        .any(|ip| ip_blocked(*ip, egress.dev_loopback, &egress.allow_cidrs))
    {
        return Err(WorkspaceError::Invalid(
            "refusing a clone URL that resolves to a private/loopback/link-local address".into(),
        ));
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
    egress: &GitEgressPolicy,
) -> Result<MaterializedWorkspace, WorkspaceError> {
    // Cheap, pure hygiene (ref/sha arg-injection) BEFORE the clone-URL check,
    // whose https branch may resolve DNS — fail fast, and never resolve a host
    // for a request already doomed by a malformed ref/sha.
    if let Some(r) = reference {
        validate_ref(r)?;
    }
    if let Some(sha) = commit_sha {
        validate_commit_sha(sha)?;
    }
    validate_clone_url(clone_url, egress)?;

    let root = session_workspace_root(data_dir, session);
    let dest = root.join("repo");
    // Idempotent retry: a partial previous attempt is discarded wholesale.
    if root.exists() {
        std::fs::remove_dir_all(&root)?;
    }
    std::fs::create_dir_all(&dest)?;

    let result = fetch_and_checkout(&dest, clone_url, reference, commit_sha, auth_header, egress);
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
    egress: &GitEgressPolicy,
) -> Result<MaterializedWorkspace, WorkspaceError> {
    // The fetch env carries the credential (GIT_CONFIG_* http.extraheader — never
    // argv/on-disk) plus, when configured, the egress proxy. Non-fetch git ops
    // (init/checkout/config) do no network, so they don't need either.
    let mut fetch_env: Vec<(String, String)> = match auth_header {
        Some(h) => vec![
            ("GIT_CONFIG_COUNT".into(), "1".into()),
            ("GIT_CONFIG_KEY_0".into(), "http.extraheader".into()),
            ("GIT_CONFIG_VALUE_0".into(), format!("Authorization: {h}")),
        ],
        None => vec![],
    };
    if let Some(proxy) = &egress.proxy {
        fetch_env.push(("HTTPS_PROXY".into(), proxy.clone()));
        fetch_env.push(("https_proxy".into(), proxy.clone()));
    }

    run_git(dest, &["init", "-q"])?;
    run_git(dest, &["remote", "add", "origin", clone_url])?;

    // Every fetch below goes through `run_fetch`, which prefixes the mandatory
    // `-c http.followRedirects=false` guard (see `fetch_argv`): a smart-HTTP
    // fetch must not follow a 3xx onto an unvalidated (internal) host.
    match commit_sha {
        Some(sha) => {
            // Exact-commit checkout (e.g. a PR head, immune to branch moves).
            // GitHub serves arbitrary SHAs shallow; generic servers may not,
            // so fall back to a full branch fetch and resolve the SHA there.
            let shallow = run_fetch(
                dest,
                &["fetch", "-q", "--depth", "1", "origin", sha],
                &fetch_env,
            );
            if shallow.is_err() {
                run_fetch(
                    dest,
                    &[
                        "fetch",
                        "-q",
                        "origin",
                        "+refs/heads/*:refs/remotes/origin/*",
                    ],
                    &fetch_env,
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
            run_fetch(
                dest,
                &["fetch", "-q", "--depth", "1", "origin", target],
                &fetch_env,
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

    save_pristine_baseline(dest)?;

    Ok(MaterializedWorkspace {
        file_count: count_files(dest),
        host_dir: dest.to_path_buf(),
        base_commit,
    })
}

/// Remove a session's workspace directory (repo + baseline + collection
/// scratch). Idempotent: missing dir is fine. Only ever touches
/// `<data_dir>/workspaces/<session>` by construction.
pub fn cleanup_workspace(data_dir: &Path, session: Uuid) -> Result<(), WorkspaceError> {
    let root = session_workspace_root(data_dir, session);
    match std::fs::remove_dir_all(&root) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
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

/// Full recursive copy INCLUDING dotfiles and `.git` internals (used for the
/// baseline). Symlinks are not followed (skipped): the baseline only needs
/// git's own object/ref/config files, which git never writes as symlinks.
fn copy_dir_all(src: &Path, dst: &Path) -> Result<(), WorkspaceError> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        let meta = std::fs::symlink_metadata(&from)?;
        if meta.is_symlink() {
            continue;
        }
        if meta.is_dir() {
            copy_dir_all(&from, &to)?;
        } else {
            std::fs::copy(&from, &to)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // I1b: assert on what the PRODUCTION fetch/env builders return (no parallel
    // constants). `run_fetch` builds every network fetch through `fetch_argv`,
    // and `run_git_env` applies `transport_hardening_env` — so these break the
    // moment the SSRF flag or the LFS/protocol env is dropped from the real path.
    #[test]
    fn fetch_argv_prefixes_the_redirect_guard() {
        let argv = fetch_argv(&["fetch", "-q", "--depth", "1", "origin", "main"]);
        // The guard is the first `-c` pair, ahead of the fetch subcommand.
        assert_eq!(
            &argv[..2],
            &["-c".to_string(), "http.followRedirects=false".to_string()]
        );
        assert!(argv.contains(&"http.followRedirects=false".to_string()));
        assert_eq!(argv.last().unwrap(), "main"); // the tail is preserved intact
    }

    #[test]
    fn transport_hardening_env_pins_lfs_and_protocol() {
        let env = transport_hardening_env();
        assert!(env.contains(&("GIT_LFS_SKIP_SMUDGE", "1")), "{env:?}");
        assert!(
            env.contains(&("GIT_ALLOW_PROTOCOL", "http:https:file")),
            "{env:?}"
        );
    }

    /// The loopback-dev clone policy the e2e runs under: file:// and loopback
    /// http both allowed. Keeps the existing tests (file:// fixtures) network-free.
    fn dev_egress() -> GitEgressPolicy {
        GitEgressPolicy {
            dev_loopback: true,
            allow_cidrs: vec![],
            clone_base_file_prefix: None,
            proxy: None,
        }
    }

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

    fn collect(ws: &MaterializedWorkspace, base: Option<&str>) -> CollectionOutcome {
        collect_diff(ws.host_dir.parent().unwrap(), base, &DiffCaps::default())
    }

    fn diff_of(out: CollectionOutcome) -> String {
        match out {
            CollectionOutcome::Diff(d) => d.patch,
            CollectionOutcome::Missing { reason } => panic!("expected diff, missing: {reason}"),
        }
    }

    #[test]
    fn materialize_git_default_head() {
        let tmp = std::env::temp_dir().join(format!("fbx-git-test-{}", Uuid::now_v7()));
        let (url, _first, head) = git_fixture(&tmp);
        let data = tmp.join("data");
        let session = Uuid::now_v7();

        let ws = materialize_git(&data, session, &url, None, None, None, &dev_egress()).unwrap();
        assert_eq!(ws.base_commit.as_deref(), Some(head.as_str()));
        assert_eq!(
            std::fs::read_to_string(ws.host_dir.join("a.txt")).unwrap(),
            "two\n"
        );
        // The sandbox copy has no remote to push to.
        assert_eq!(run_git(&ws.host_dir, &["remote"]).unwrap(), "");
        // The pristine baseline exists beside the repo.
        assert!(ws
            .host_dir
            .parent()
            .unwrap()
            .join(BASELINE_DIR)
            .join("HEAD")
            .exists());

        // Diff capture works over the pristine baseline.
        std::fs::write(ws.host_dir.join("a.txt"), "three\n").unwrap();
        let diff = diff_of(collect(&ws, ws.base_commit.as_deref()));
        assert!(diff.contains("three"));

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn materialize_git_exact_ref_and_exact_commit() {
        let tmp = std::env::temp_dir().join(format!("fbx-git-test-{}", Uuid::now_v7()));
        let (url, first, head) = git_fixture(&tmp);
        let data = tmp.join("data");

        // Branch ref → that branch's head, not the default branch.
        let by_ref = materialize_git(
            &data,
            Uuid::now_v7(),
            &url,
            Some("feature"),
            None,
            None,
            &dev_egress(),
        )
        .unwrap();
        assert_eq!(by_ref.base_commit.as_deref(), Some(first.as_str()));
        assert_eq!(
            std::fs::read_to_string(by_ref.host_dir.join("a.txt")).unwrap(),
            "one\n"
        );

        // Exact commit → exactly that commit, immune to branch movement
        // (file:// doesn't serve arbitrary SHAs shallow — exercises the
        // full-fetch fallback).
        let by_sha = materialize_git(
            &data,
            Uuid::now_v7(),
            &url,
            None,
            Some(&first),
            None,
            &dev_egress(),
        )
        .unwrap();
        assert_eq!(by_sha.base_commit.as_deref(), Some(first.as_str()));
        assert_eq!(
            std::fs::read_to_string(by_sha.host_dir.join("a.txt")).unwrap(),
            "one\n"
        );
        // ref+sha together: sha wins (it's the more exact pin).
        let both = materialize_git(
            &data,
            Uuid::now_v7(),
            &url,
            Some("main"),
            Some(&head),
            None,
            &dev_egress(),
        )
        .unwrap();
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
            &dev_egress(),
        );
        assert!(err.is_err());
        assert!(
            !data.join("workspaces").join(session.to_string()).exists(),
            "failed clone must not leave a partial workspace"
        );

        // Bad commit in a good repo also cleans up.
        let (url, ..) = git_fixture(&tmp);
        let err = materialize_git(
            &data,
            session,
            &url,
            None,
            Some("deadbeefdeadbeef"),
            None,
            &dev_egress(),
        );
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
                materialize_git(&data, sid, url, None, None, None, &dev_egress()),
                Err(WorkspaceError::Invalid(_))
            ));
        }
        // Option-shaped / malformed refs and shas. The https host is never
        // resolved here — the ref/sha hygiene fails first (validation ordering).
        for r in ["-evil", "a b", "a..b", "x:y"] {
            assert!(matches!(
                materialize_git(
                    &data,
                    sid,
                    "https://github.com/o/r.git",
                    Some(r),
                    None,
                    None,
                    &dev_egress()
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
                    None,
                    &dev_egress()
                ),
                Err(WorkspaceError::Invalid(_))
            ));
        }
        std::fs::remove_dir_all(&tmp).ok();
    }

    /// E4: the clone-URL egress policy — https host validation, the dev-loopback
    /// http seam, the file:// clone-base gate, and the allow-CIDR override. All
    /// cases use IP literals or file paths, so no DNS resolution occurs.
    #[test]
    fn clone_url_egress_policy() {
        let dev = dev_egress();
        let prod = GitEgressPolicy {
            dev_loopback: false,
            allow_cidrs: vec![],
            clone_base_file_prefix: Some("file:///srv/mirror".into()),
            proxy: None,
        };

        // https to a private/loopback/metadata IP literal is refused (prod)…
        assert!(validate_clone_url("https://10.0.0.1/r.git", &prod).is_err());
        assert!(validate_clone_url("https://169.254.169.254/r.git", &prod).is_err());
        assert!(validate_clone_url("https://[::1]/r.git", &prod).is_err());
        // …and metadata stays refused even in dev (loopback ≠ link-local).
        assert!(validate_clone_url("http://169.254.169.254/r.git", &dev).is_err());
        // loopback http is allowed ONLY under the dev seam.
        assert!(validate_clone_url("http://127.0.0.1:9/r.git", &dev).is_ok());
        assert!(validate_clone_url("http://127.0.0.1:9/r.git", &prod).is_err());

        // file:// — dev allows any; prod only under the configured clone base.
        assert!(validate_clone_url("file:///tmp/x", &dev).is_ok());
        assert!(validate_clone_url("file:///tmp/x", &prod).is_err());
        assert!(validate_clone_url("file:///srv/mirror/o/r.git", &prod).is_ok());

        // Other schemes and option-injection are refused regardless of seam.
        assert!(validate_clone_url("ssh://h/r.git", &dev).is_err());
        assert!(validate_clone_url("--upload-pack=evil", &dev).is_err());

        // FALSE-GREEN guard: the SAME private https literal that is refused above
        // is admitted once an allow-CIDR covers it.
        let allowed = GitEgressPolicy {
            dev_loopback: false,
            allow_cidrs: vec!["10.0.0.0/8".parse().unwrap()],
            clone_base_file_prefix: None,
            proxy: None,
        };
        assert!(validate_clone_url("https://10.0.0.1/r.git", &prod).is_err());
        assert!(validate_clone_url("https://10.0.0.1/r.git", &allowed).is_ok());
    }

    #[test]
    fn cleanup_workspace_is_idempotent() {
        let tmp = std::env::temp_dir().join(format!("fbx-git-test-{}", Uuid::now_v7()));
        let (url, ..) = git_fixture(&tmp);
        let data = tmp.join("data");
        let session = Uuid::now_v7();
        materialize_git(&data, session, &url, None, None, None, &dev_egress()).unwrap();
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

        let diff = diff_of(collect(&ws, ws.base_commit.as_deref()));
        assert!(diff.contains("a.txt"));
        assert!(diff.contains("b.txt"));
        assert!(diff.contains("hello world"));

        std::fs::remove_dir_all(&tmp).ok();
    }
}
