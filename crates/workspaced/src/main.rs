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

use fluidbox_workspace::{
    collect_diff_at, unpack_archive, verify_archive, CollectionOutcome, DiffCaps,
};
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
    let bytes = fetch(&url, &token, expected_len)?;
    verify_archive(&bytes, expected_len, &expected_sha).map_err(|e| e.to_string())?;

    // Unpack into a collector-local staging dir (same volume → cheap rename
    // for the baseline; cross-volume copy for the worktree).
    let stage = collector.join("unpack");
    if stage.exists() {
        std::fs::remove_dir_all(&stage).ok();
    }
    unpack_archive(&bytes, &stage, MAX_UNPACK_BYTES).map_err(|e| e.to_string())?;

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

/// GET the archive with the session token, bounding the body at the declared
/// length (+slack) so a lying Content-Length can't exhaust memory.
fn fetch(url: &str, token: &str, expected_len: u64) -> Result<Vec<u8>, String> {
    let resp = ureq::get(url)
        .set("authorization", &format!("Bearer {token}"))
        .timeout(std::time::Duration::from_secs(120))
        .call()
        .map_err(|e| format!("archive GET failed: {e}"))?;
    let cap = expected_len.saturating_add(1024) as usize;
    let mut buf = Vec::with_capacity(expected_len as usize);
    resp.into_reader()
        .take(cap as u64)
        .read_to_end(&mut buf)
        .map_err(|e| format!("archive read failed: {e}"))?;
    Ok(buf)
}

/// Recursive copy including dotfiles + `.git` internals. In-tree symlinks are
/// PRESERVED (H4: a tracked symlink must reach the runner's /workspace exactly
/// as Docker's bind mount delivers it). A symlink is recreated only if its
/// target still resolves within `dst_root`; because relocating `repo/` to
/// /workspace shrinks the root the extractor validated against, a link that
/// pointed outside `repo/` (into the baseline, say) is dropped rather than left
/// to escape.
fn copy_tree(src: &Path, dst: &Path) -> std::io::Result<()> {
    copy_tree_into(src, dst, dst)
}

fn copy_tree_into(src: &Path, dst: &Path, dst_root: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        let meta = std::fs::symlink_metadata(&from)?;
        if meta.is_symlink() {
            copy_symlink(&from, &to, dst_root)?;
        } else if meta.is_dir() {
            copy_tree_into(&from, &to, dst_root)?;
        } else {
            std::fs::copy(&from, &to)?;
        }
    }
    Ok(())
}

/// Recreate one symlink under the new root, preserving it iff its target
/// resolves within `dst_root`. The containment walk is shared with the archive
/// extractor (`fluidbox_workspace::target_within_root`); the real starting
/// depth comes from canonicalizing the link's (already-created) parent dir.
#[cfg(unix)]
fn copy_symlink(from: &Path, to: &Path, dst_root: &Path) -> std::io::Result<()> {
    let target = std::fs::read_link(from)?;
    let contained = (|| {
        let canon_root = std::fs::canonicalize(dst_root).ok()?;
        let canon_parent = std::fs::canonicalize(to.parent()?).ok()?;
        let rel = canon_parent.strip_prefix(&canon_root).ok()?;
        let depth = rel
            .components()
            .filter(|c| matches!(c, std::path::Component::Normal(_)))
            .count() as i64;
        Some(fluidbox_workspace::target_within_root(depth, &target))
    })()
    .unwrap_or(false);
    if contained {
        std::os::unix::fs::symlink(&target, to)?;
    } else {
        eprintln!(
            "workspaced: dropping symlink {} -> {} (target escapes the workspace root)",
            to.display(),
            target.display()
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn copy_symlink(_from: &Path, _to: &Path, _dst_root: &Path) -> std::io::Result<()> {
    Ok(())
}

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
        // Points above the copy root → must be dropped, not escape /workspace.
        std::os::unix::fs::symlink("../../etc/passwd", src.join("escape")).unwrap();

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
        assert!(
            std::fs::symlink_metadata(dst.join("escape")).is_err(),
            "escaping symlink must be dropped"
        );
        std::fs::remove_dir_all(&base).ok();
    }
}
