//! `workspaced` — the fluidbox in-pod workspace collector (design 2026-07-15).
//!
//! One tiny binary, four subcommands, run inside the sandbox Pod's
//! collector/init containers:
//!
//!   workspaced init    — pull the immutable archive from the control plane,
//!                        verify size+digest, unpack into /workspace with the
//!                        hardened extractor, and stash the pristine `.git`
//!                        baseline in the collector-only volume.
//!   workspaced wait    — long-lived no-op: keeps the collector container (and
//!                        thus the Pod) Running after the runner exits, so the
//!                        control plane can exec collection.
//!   workspaced diff    — reconstruct the diff from the pristine baseline +
//!                        final worktree (never the agent's `.git`) and write
//!                        it atomically to the collector-only output file.
//!   workspaced stream  — emit that finished file from `--offset N`, so the
//!                        control plane's `pods/exec` collection resumes on a
//!                        dropped stream.
//!
//! The runner NEVER sees the baseline volume; the collector NEVER holds a
//! credential (the session token authenticates only the one archive GET, in
//! the init container). Extraction + diff policy live in `fluidbox-workspace`,
//! auditable in one place and shared with the Docker provider.

use fluidbox_workspace::{collect_diff_at, unpack_archive_reader, CollectionOutcome, DiffCaps};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// Cap the archive unpack — a decompression bomb wastes this, never the node.
const MAX_UNPACK_BYTES: u64 = 4 * 1024 * 1024 * 1024;

fn env(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}

fn require(key: &str) -> Result<String, String> {
    env(key).ok_or_else(|| format!("missing required env {key}"))
}

fn workspace_dir() -> PathBuf {
    PathBuf::from(env("FLUIDBOX_WORKSPACE").unwrap_or_else(|| "/workspace".into()))
}

fn collector_dir() -> PathBuf {
    PathBuf::from(env("FLUIDBOX_COLLECTOR_DIR").unwrap_or_else(|| "/collector".into()))
}

fn baseline_dir() -> PathBuf {
    collector_dir().join("baseline")
}

fn out_file() -> PathBuf {
    collector_dir().join("out").join("diff")
}

fn main() -> ExitCode {
    let cmd = std::env::args().nth(1).unwrap_or_default();
    let result = match cmd.as_str() {
        "init" => cmd_init(),
        "wait" => cmd_wait(),
        "diff" => cmd_diff(),
        "stream" => cmd_stream(),
        other => Err(format!(
            "usage: workspaced <init|wait|diff|stream>; got '{other}'"
        )),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("workspaced: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Pull + verify + unpack the immutable workspace archive, then stash the
/// pristine baseline. Corrupt/oversized/unsafe archives fail here → the init
/// container fails → the Pod fails → the run fails at zero model spend
/// (preserving the "bad repo costs nothing" property).
fn cmd_init() -> Result<(), String> {
    let url = require("FLUIDBOX_WORKSPACE_ARCHIVE_URL")?;
    let token = require("FLUIDBOX_SESSION_TOKEN")?;
    let expected_sha = require("FLUIDBOX_ARCHIVE_SHA256")?;
    let expected_len: u64 = require("FLUIDBOX_ARCHIVE_LEN")?
        .parse()
        .map_err(|e| format!("bad FLUIDBOX_ARCHIVE_LEN: {e}"))?;
    let workspace = workspace_dir();
    let collector = collector_dir();

    eprintln!("workspaced init: fetching archive ({expected_len} bytes)");
    // Stream to the collector volume (disk-backed emptyDir), hashing as it
    // lands — the archive never sits in init-container RAM (M4's pod half:
    // a near-cap archive used to consume the whole container memory limit).
    let archive_file = collector.join("archive.tar.gz");
    std::fs::create_dir_all(&collector).map_err(|e| e.to_string())?;
    fetch_to_file(&url, &token, expected_len, &expected_sha, &archive_file)?;

    // Unpack into a collector-local staging dir (same volume → cheap rename
    // for the baseline; cross-volume copy for the worktree), streaming off
    // the verified file.
    let stage = collector.join("unpack");
    if stage.exists() {
        std::fs::remove_dir_all(&stage).ok();
    }
    let f = std::fs::File::open(&archive_file).map_err(|e| e.to_string())?;
    unpack_archive_reader(f, &stage, MAX_UNPACK_BYTES).map_err(|e| e.to_string())?;
    std::fs::remove_file(&archive_file).ok();

    // repo/ (worktree incl. its .git) → /workspace (the runner's tree).
    let repo = stage.join("repo");
    if !repo.is_dir() {
        return Err("archive has no repo/ entry".into());
    }
    std::fs::create_dir_all(&workspace).map_err(|e| e.to_string())?;
    copy_tree(&repo, &workspace).map_err(|e| format!("populate workspace: {e}"))?;

    // baseline-git/ → /collector/baseline (collector+init only; the runner
    // never sees it, so agent mutations to /workspace/.git can't touch it).
    let baseline_src = stage.join(fluidbox_workspace::BASELINE_DIR);
    let baseline_dst = baseline_dir();
    if baseline_src.is_dir() {
        if baseline_dst.exists() {
            std::fs::remove_dir_all(&baseline_dst).ok();
        }
        std::fs::rename(&baseline_src, &baseline_dst)
            .or_else(|_| copy_tree(&baseline_src, &baseline_dst))
            .map_err(|e| format!("stage baseline: {e}"))?;
    } else {
        eprintln!(
            "workspaced init: WARN no baseline-git in archive; collection will report missing"
        );
    }

    std::fs::remove_dir_all(&stage).ok();
    eprintln!("workspaced init: workspace ready");
    Ok(())
}

/// Keep the collector container alive so the control plane can exec `diff` +
/// `stream` after the runner exits. Ends only when the Pod is deleted.
fn cmd_wait() -> Result<(), String> {
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}

/// Compute the diff (pristine baseline + final worktree, scrubbed git) and
/// write it atomically to the collector-only output file. Idempotent: a
/// re-exec recomputes and replaces.
fn cmd_diff() -> Result<(), String> {
    let workspace = workspace_dir();
    let baseline = baseline_dir();
    let collector = collector_dir();
    let base_commit = env("FLUIDBOX_BASE_COMMIT");

    let outcome = collect_diff_at(
        &workspace,
        &baseline,
        &collector,
        base_commit.as_deref(),
        &DiffCaps::default(),
    );

    let out = out_file();
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    // A sidecar header line lets the control plane distinguish a real diff
    // from an explicit missing marker without a second channel.
    let (header, body): (String, String) = match outcome {
        CollectionOutcome::Diff(d) => (
            format!(
                "fluidbox-diff v1 status=ok bytes={} sha256={} truncated={}\n",
                d.bytes, d.sha256, d.truncated
            ),
            d.patch,
        ),
        CollectionOutcome::Missing { reason } => (
            format!(
                "fluidbox-diff v1 status=missing reason={}\n",
                oneline(&reason)
            ),
            String::new(),
        ),
    };

    let tmp = out.with_extension("tmp");
    {
        let mut f = std::fs::File::create(&tmp).map_err(|e| e.to_string())?;
        f.write_all(header.as_bytes()).map_err(|e| e.to_string())?;
        f.write_all(body.as_bytes()).map_err(|e| e.to_string())?;
        f.sync_all().ok();
    }
    std::fs::rename(&tmp, &out).map_err(|e| format!("atomic publish: {e}"))?;
    Ok(())
}

/// Emit the finished diff file from `--offset N` (default 0). The control
/// plane collects over `pods/exec`; if the stream drops it re-execs with the
/// bytes it already has, so collection is resumable and decoupled from the
/// fragile exec channel.
fn cmd_stream() -> Result<(), String> {
    let mut offset: u64 = 0;
    let args: Vec<String> = std::env::args().skip(2).collect();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--offset" {
            offset = args
                .get(i + 1)
                .and_then(|s| s.parse().ok())
                .ok_or("--offset needs a number")?;
            i += 2;
        } else {
            i += 1;
        }
    }
    let out = out_file();
    let mut f = std::fs::File::open(&out)
        .map_err(|e| format!("diff not computed yet ({}): {e}", out.display()))?;
    f.seek(SeekFrom::Start(offset)).map_err(|e| e.to_string())?;
    let mut stdout = std::io::stdout().lock();
    std::io::copy(&mut f, &mut stdout).map_err(|e| e.to_string())?;
    stdout.flush().map_err(|e| e.to_string())?;
    Ok(())
}

/// GET the archive with the session token, STREAMING it to `dest` while
/// hashing — never buffered in RAM. The body is bounded at the declared
/// length (+slack) so a lying server can't exhaust the volume, and size +
/// digest are verified against the RunSpec-carried expectations before Ok.
/// No overall deadline (a large archive on a modest link outlives any fixed
/// budget; the Pod's activeDeadlineSeconds bounds all of init) — but a
/// STALLED connection dies on the per-read timeout.
fn fetch_to_file(
    url: &str,
    token: &str,
    expected_len: u64,
    expected_sha: &str,
    dest: &Path,
) -> Result<(), String> {
    use sha2::Digest;
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(std::time::Duration::from_secs(10))
        .timeout_read(std::time::Duration::from_secs(60))
        .build();
    let resp = agent
        .get(url)
        .set("authorization", &format!("Bearer {token}"))
        .call()
        .map_err(|e| format!("archive GET failed: {e}"))?;
    let mut reader = resp.into_reader().take(expected_len.saturating_add(1024));
    let file =
        std::fs::File::create(dest).map_err(|e| format!("create {}: {e}", dest.display()))?;
    let mut out = std::io::BufWriter::new(file);
    let mut hasher = sha2::Sha256::new();
    let mut len: u64 = 0;
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|e| format!("archive read failed: {e}"))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        out.write_all(&buf[..n])
            .map_err(|e| format!("archive write failed: {e}"))?;
        len += n as u64;
    }
    out.flush()
        .map_err(|e| format!("archive flush failed: {e}"))?;
    if len != expected_len {
        let _ = std::fs::remove_file(dest);
        return Err(format!("archive size {len} != expected {expected_len}"));
    }
    let got = format!("sha256:{}", hex::encode(hasher.finalize()));
    if got != expected_sha {
        let _ = std::fs::remove_file(dest);
        return Err("archive digest mismatch — refusing to unpack".into());
    }
    Ok(())
}

/// Recursive copy including dotfiles + `.git` internals. In-tree symlinks are
/// PRESERVED (H4: a tracked symlink must reach the runner's /workspace exactly
/// as Docker's bind mount delivers it), using the same two-phase approach as
/// the archive extractor: copy every real file/dir first, then create the
/// symlinks and keep only those that `canonicalize` inside `dst`. Relocating
/// `repo/` to /workspace shrinks the root the extractor validated against, so
/// a link that pointed outside `repo/` (into the baseline, say) is dropped
/// rather than left to escape. `canonicalize` — following the FULL target
/// chain — is the sole containment judge.
fn copy_tree(src: &Path, dst: &Path) -> std::io::Result<()> {
    // Fresh-destination precondition (fail-closed): on an init re-execution the
    // surviving emptyDir may hold runner-planted symlinks; clear dst's contents
    // FIRST (which refuses a symlinked `dst` itself, so we never copy through a
    // symlink to outside), THEN ensure a real dir.
    fluidbox_workspace::clear_dir_contents(dst)?;
    std::fs::create_dir_all(dst)?;
    let mut symlinks: Vec<(PathBuf, PathBuf)> = Vec::new();
    copy_files(src, dst, &mut symlinks)?;
    place_symlinks(dst, &symlinks);
    Ok(())
}

fn copy_files(
    src: &Path,
    dst: &Path,
    symlinks: &mut Vec<(PathBuf, PathBuf)>,
) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        let meta = std::fs::symlink_metadata(&from)?;
        if meta.is_symlink() {
            symlinks.push((to, std::fs::read_link(&from)?));
        } else if meta.is_dir() {
            copy_files(&from, &to, symlinks)?;
        } else {
            std::fs::copy(&from, &to)?;
        }
    }
    Ok(())
}

/// Create the collected symlinks, then keep only those that resolve inside
/// `dst_root` (per `canonicalize`, following the whole chain). Parent must
/// already exist and resolve in-root, so creation never writes through an
/// escaping link.
#[cfg(unix)]
fn place_symlinks(dst_root: &Path, symlinks: &[(PathBuf, PathBuf)]) {
    let Ok(canon_root) = std::fs::canonicalize(dst_root) else {
        return;
    };
    let mut created: Vec<PathBuf> = Vec::new();
    for (to, target) in symlinks {
        let Some(parent) = to.parent() else { continue };
        match std::fs::canonicalize(parent) {
            Ok(cp) if cp.starts_with(&canon_root) => {}
            _ => continue,
        }
        if std::os::unix::fs::symlink(target, to).is_ok() {
            created.push(to.clone());
        }
    }
    for to in created {
        match std::fs::canonicalize(&to) {
            Ok(real) if real.starts_with(&canon_root) => {}
            _ => {
                eprintln!(
                    "workspaced: dropping symlink {} (target escapes the workspace root)",
                    to.display()
                );
                std::fs::remove_file(&to).ok();
            }
        }
    }
}

#[cfg(not(unix))]
fn place_symlinks(_dst_root: &Path, _symlinks: &[(PathBuf, PathBuf)]) {}

fn oneline(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_whitespace() { ' ' } else { c })
        .take(200)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// H4 (K8s path): `cmd_init` copies the extracted `repo/` into /workspace
    /// via `copy_tree`, which previously SKIPPED symlinks — so a tracked
    /// in-tree symlink never reached the runner even after the extractor
    /// created it. `copy_tree` must now preserve in-tree links and drop only
    /// those whose target escapes the new (smaller) /workspace root.
    #[cfg(unix)]
    #[test]
    fn copy_tree_preserves_intree_symlink_and_drops_escaping() {
        let base = std::env::temp_dir().join(format!("fbx-copytree-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let src = base.join("src");
        std::fs::create_dir_all(src.join("sub")).unwrap();
        std::fs::write(src.join("a.txt"), "hi\n").unwrap();
        std::os::unix::fs::symlink("a.txt", src.join("link")).unwrap();
        std::os::unix::fs::symlink("../a.txt", src.join("sub/uplink")).unwrap();
        // A REAL file outside the copy root — the escaping links must resolve
        // to it (so canonicalize succeeds and proves containment) yet be
        // dropped. Deterministic, unlike a target that merely dangles.
        std::fs::write(base.join("secret.txt"), "SECRET\n").unwrap();
        // Points above the copy root → dropped.
        std::os::unix::fs::symlink("../secret.txt", src.join("escape")).unwrap();
        // Codex batch-3v2 counterexample: a symlinked component in the target.
        // `anchor -> .`, `leak -> anchor/../secret.txt` resolves OUT via anchor
        // — lexical math accepts it; canonicalize refuses.
        std::os::unix::fs::symlink(".", src.join("anchor")).unwrap();
        std::os::unix::fs::symlink("anchor/../secret.txt", src.join("leak")).unwrap();

        let dst = base.join("workspace");
        copy_tree(&src, &dst).unwrap();

        let link = dst.join("link");
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink(),
            "in-tree symlink must be preserved"
        );
        assert_eq!(std::fs::read_to_string(&link).unwrap(), "hi\n");
        assert!(
            std::fs::symlink_metadata(dst.join("sub/uplink"))
                .unwrap()
                .file_type()
                .is_symlink(),
            "in-tree ../ symlink must be preserved"
        );
        assert!(std::fs::read_to_string(src.join("a.txt")).is_ok());
        // The escaping links resolved to the REAL outside file yet were dropped.
        for bad in ["escape", "leak"] {
            assert!(
                std::fs::symlink_metadata(dst.join(bad)).is_err(),
                "escaping symlink {bad} must be dropped"
            );
        }
        assert_eq!(
            std::fs::read_to_string(base.join("secret.txt")).unwrap(),
            "SECRET\n",
            "the outside file must be untouched"
        );
        std::fs::remove_dir_all(&base).ok();
    }

    /// Codex batch-3v3 finding 1: an init re-execution over a DIRTY /workspace
    /// (the emptyDir survives Pod restarts) must not let the copy phase follow
    /// a runner-planted symlink out of the root. `copy_tree` clears dst's
    /// contents first, so copying a regular `seed` writes a fresh file instead
    /// of overwriting the outside canary through the stale link.
    #[cfg(unix)]
    #[test]
    fn copy_tree_clears_stale_destination_symlink() {
        let base = std::env::temp_dir().join(format!("fbx-copystale-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let src = base.join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("seed"), "fresh\n").unwrap();

        // Outside canary + a dirty dst where the runner planted `seed` as a
        // symlink pointing at it.
        std::fs::write(base.join("canary"), "ORIGINAL\n").unwrap();
        let dst = base.join("workspace");
        std::fs::create_dir_all(&dst).unwrap();
        std::os::unix::fs::symlink(base.join("canary"), dst.join("seed")).unwrap();

        copy_tree(&src, &dst).unwrap();

        // The planted link is gone; seed is a real file; the canary is intact.
        assert!(
            !std::fs::symlink_metadata(dst.join("seed"))
                .unwrap()
                .file_type()
                .is_symlink(),
            "stale destination symlink must be cleared"
        );
        assert_eq!(
            std::fs::read_to_string(dst.join("seed")).unwrap(),
            "fresh\n"
        );
        assert_eq!(
            std::fs::read_to_string(base.join("canary")).unwrap(),
            "ORIGINAL\n",
            "copy must not follow the stale link and overwrite the canary"
        );
        std::fs::remove_dir_all(&base).ok();
    }
}
