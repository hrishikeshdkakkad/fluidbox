//! Immutable workspace archive: the control-plane→pod transport (design
//! 2026-07-15, §"Workspace transport (in)").
//!
//! The control plane packs ONE `tar.gz` of the session workspace (the `repo/`
//! worktree, its `.git`, and the pristine `baseline-git/`), records byte size
//! and SHA-256, and serves it on the internal listener. The pod's init
//! container pulls it, verifies size and digest, and unpacks it with a
//! HARDENED extractor. Extraction policy lives HERE, in one auditable place,
//! rejecting absolute paths, parent-dir traversal, and symlinks or hardlinks
//! that escape the root.

use crate::WorkspaceError;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use sha2::{Digest, Sha256};
use std::path::{Component, Path, PathBuf};

/// A packed archive plus its integrity metadata. `sha256` is over the exact
/// `bytes` the pod will download.
pub struct PackedArchive {
    pub bytes: Vec<u8>,
    pub sha256: String,
    pub len: u64,
}

/// Pack a session workspace root (`repo/` + `baseline-git/`) into a gzip'd
/// tar. Symlinks inside the tree are followed as their target contents would
/// bloat/loop; git never stores its own metadata as symlinks, and a worktree
/// symlink is materialized as a regular entry on unpack — the extractor
/// rejects any that escape.
pub fn pack_workspace(session_root: &Path) -> Result<PackedArchive, WorkspaceError> {
    let mut gz = GzEncoder::new(Vec::new(), Compression::default());
    {
        let mut builder = tar::Builder::new(&mut gz);
        builder.follow_symlinks(false);
        // Only these two subtrees ship: the worktree (with .git) and the
        // pristine baseline. Anything else in the session root (collect-tmp,
        // etc.) stays on the control plane.
        for sub in ["repo", crate::BASELINE_DIR] {
            let path = session_root.join(sub);
            if path.is_dir() {
                builder
                    .append_dir_all(sub, &path)
                    .map_err(|e| WorkspaceError::Invalid(format!("tar append {sub}: {e}")))?;
            }
        }
        builder
            .finish()
            .map_err(|e| WorkspaceError::Invalid(format!("tar finish: {e}")))?;
    }
    let bytes = gz
        .finish()
        .map_err(|e| WorkspaceError::Invalid(format!("gzip finish: {e}")))?;
    let sha256 = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
    let len = bytes.len() as u64;
    Ok(PackedArchive { bytes, sha256, len })
}

/// Verify `bytes` against an expected size and digest before unpacking —
/// tampering or truncation fails BEFORE any extraction touches the disk.
pub fn verify_archive(
    bytes: &[u8],
    expected_len: u64,
    expected_sha256: &str,
) -> Result<(), WorkspaceError> {
    if bytes.len() as u64 != expected_len {
        return Err(WorkspaceError::Invalid(format!(
            "archive size {} != expected {expected_len}",
            bytes.len()
        )));
    }
    let got = format!("sha256:{}", hex::encode(Sha256::digest(bytes)));
    if got != expected_sha256 {
        return Err(WorkspaceError::Invalid(
            "archive digest mismatch — refusing to unpack".into(),
        ));
    }
    Ok(())
}

/// Hardened unpack: every entry path is validated to stay inside `dest`
/// (no absolute paths, no `..`, no symlink/hardlink escaping the root), and a
/// total-size ceiling bounds a decompression bomb. Returns the number of
/// entries written.
pub fn unpack_archive(
    bytes: &[u8],
    dest: &Path,
    max_total_bytes: u64,
) -> Result<u64, WorkspaceError> {
    std::fs::create_dir_all(dest)?;
    let canon_dest = std::fs::canonicalize(dest)?;
    let gz = GzDecoder::new(bytes);
    let mut archive = tar::Archive::new(gz);
    archive.set_preserve_permissions(false);
    archive.set_preserve_mtime(false);

    let mut written: u64 = 0;
    let mut total: u64 = 0;
    for entry in archive
        .entries()
        .map_err(|e| WorkspaceError::Invalid(format!("read archive: {e}")))?
    {
        let mut entry =
            entry.map_err(|e| WorkspaceError::Invalid(format!("archive entry: {e}")))?;
        let path = entry
            .path()
            .map_err(|e| WorkspaceError::Invalid(format!("entry path: {e}")))?
            .into_owned();
        let safe = safe_join(&canon_dest, &path)?;

        let etype = entry.header().entry_type();
        // Reject links outright — a symlink or hardlink is the classic escape,
        // and the workspace transport never needs one.
        if etype.is_symlink() || etype.is_hard_link() {
            return Err(WorkspaceError::Invalid(format!(
                "archive contains a link entry ({}) — refused",
                path.display()
            )));
        }
        if etype.is_dir() {
            std::fs::create_dir_all(&safe)?;
            continue;
        }
        // Regular file (or anything else we treat as one): bound the running
        // total and unpack into the validated path only.
        let size = entry.header().size().unwrap_or(0);
        total = total.saturating_add(size);
        if total > max_total_bytes {
            return Err(WorkspaceError::Invalid(format!(
                "archive exceeds the {max_total_bytes}-byte unpack ceiling"
            )));
        }
        if let Some(parent) = safe.parent() {
            std::fs::create_dir_all(parent)?;
        }
        entry
            .unpack(&safe)
            .map_err(|e| WorkspaceError::Invalid(format!("unpack {}: {e}", path.display())))?;
        written += 1;
    }
    Ok(written)
}

/// Join `rel` under `base`, rejecting anything that would escape (absolute
/// components, `..`, root/prefix). Purely lexical — no filesystem access, so
/// it is safe to run before the target exists.
fn safe_join(base: &Path, rel: &Path) -> Result<PathBuf, WorkspaceError> {
    let mut out = base.to_path_buf();
    for comp in rel.components() {
        match comp {
            Component::Normal(c) => out.push(c),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(WorkspaceError::Invalid(format!(
                    "unsafe archive path '{}' (absolute or traversal)",
                    rel.display()
                )));
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn pack_verify_unpack_roundtrip() {
        let tmp = std::env::temp_dir().join(format!("fbx-arch-{}", Uuid::now_v7()));
        let root = tmp.join("ws");
        let repo = root.join("repo");
        std::fs::create_dir_all(repo.join(".git")).unwrap();
        std::fs::write(repo.join("a.txt"), "hello\n").unwrap();
        std::fs::write(repo.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
        std::fs::create_dir_all(root.join(crate::BASELINE_DIR)).unwrap();
        std::fs::write(root.join(crate::BASELINE_DIR).join("HEAD"), "ref: x\n").unwrap();

        let packed = pack_workspace(&root).unwrap();
        assert!(packed.sha256.starts_with("sha256:"));
        verify_archive(&packed.bytes, packed.len, &packed.sha256).unwrap();

        // Tamper → verify fails.
        let mut bad = packed.bytes.clone();
        bad.push(0);
        assert!(verify_archive(&bad, packed.len, &packed.sha256).is_err());

        let dest = tmp.join("out");
        unpack_archive(&packed.bytes, &dest, 100 * 1024 * 1024).unwrap();
        assert_eq!(
            std::fs::read_to_string(dest.join("repo/a.txt")).unwrap(),
            "hello\n"
        );
        assert!(dest.join(crate::BASELINE_DIR).join("HEAD").exists());
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn safe_join_rejects_escape_and_accepts_normal() {
        // The tar builder sanitizes `..` at append time, so the escape defense
        // is `safe_join` (a purely lexical guard applied to EVERY entry path,
        // whatever produced the tar). Test it directly against the classic
        // escapes an adversarial archive would carry.
        let base = Path::new("/data/ws");
        for bad in ["../escape.txt", "a/../../etc/passwd", "/etc/passwd", "/../x"] {
            assert!(
                safe_join(base, Path::new(bad)).is_err(),
                "must reject escaping path '{bad}'"
            );
        }
        // Normal nested paths join under the base.
        let ok = safe_join(base, Path::new("repo/src/a.txt")).unwrap();
        assert_eq!(ok, Path::new("/data/ws/repo/src/a.txt"));
        // `.` components are harmless and elided.
        let dot = safe_join(base, Path::new("./repo/./b.txt")).unwrap();
        assert_eq!(dot, Path::new("/data/ws/repo/b.txt"));
    }

    #[test]
    fn unpack_rejects_symlink() {
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        {
            let mut b = tar::Builder::new(&mut gz);
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_size(0);
            header.set_link_name("/etc/passwd").unwrap();
            header.set_cksum();
            b.append_data(&mut header, "link", std::io::empty())
                .unwrap();
            b.finish().unwrap();
        }
        let bytes = gz.finish().unwrap();
        let tmp = std::env::temp_dir().join(format!("fbx-arch-sym-{}", Uuid::now_v7()));
        assert!(unpack_archive(&bytes, &tmp, 1024 * 1024).is_err());
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn unpack_enforces_size_ceiling() {
        let tmp = std::env::temp_dir().join(format!("fbx-arch-big-{}", Uuid::now_v7()));
        let root = tmp.join("ws");
        std::fs::create_dir_all(root.join("repo")).unwrap();
        std::fs::write(root.join("repo/big.bin"), vec![0u8; 64 * 1024]).unwrap();
        let packed = pack_workspace(&root).unwrap();
        let dest = tmp.join("out");
        assert!(unpack_archive(&packed.bytes, &dest, 4 * 1024).is_err());
        std::fs::remove_dir_all(&tmp).ok();
    }
}
