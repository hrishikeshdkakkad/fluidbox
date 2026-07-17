//! Immutable workspace archive: the control-plane→pod transport (design
//! 2026-07-15, §"Workspace transport (in)").
//!
//! The control plane packs ONE `tar.gz` of the session workspace (the `repo/`
//! worktree, its `.git`, and the pristine `baseline-git/`), records byte size
//! and SHA-256, and serves it on the internal listener. The pod's init
//! container pulls it, verifies size and digest, and unpacks it with a
//! HARDENED extractor. Extraction policy lives HERE, in one auditable place:
//! it refuses absolute paths, parent-dir traversal in entry paths, and every
//! hardlink; symlinks are extracted only if they `canonicalize` INSIDE the
//! root (the kernel resolves the whole chain), and any that escape or dangle
//! are dropped.

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

/// A packed archive stored on disk (the production transport — the archive
/// never lives in control-plane RAM). `sha256`/`len` describe the exact file.
#[derive(Debug)]
pub struct StoredArchive {
    pub path: PathBuf,
    pub sha256: String,
    pub len: u64,
}

/// The ONE tar-assembly core (both packers ride it, so extraction policy and
/// symlink handling can never diverge between them). `follow_symlinks(false)`
/// stores each symlink as a symlink ENTRY (the target string), never
/// dereferencing it — so an in-tree relative link survives the round-trip and
/// the extractor decides per entry whether the target stays inside the root.
fn write_tar_gz<W: std::io::Write>(session_root: &Path, sink: W) -> Result<W, WorkspaceError> {
    let mut gz = GzEncoder::new(sink, Compression::default());
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
    gz.finish()
        .map_err(|e| WorkspaceError::Invalid(format!("gzip finish: {e}")))
}

/// Counting + hashing + capping write adapter: digests and measures the
/// compressed stream AS IT IS WRITTEN, and refuses the write that would push
/// the archive over `max_bytes` — the pack fails without ever holding (or
/// storing) an over-cap archive.
struct HashingWriter<W: std::io::Write> {
    inner: W,
    hasher: Sha256,
    len: u64,
    max_bytes: u64,
}

impl<W: std::io::Write> std::io::Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.len.saturating_add(buf.len() as u64) > self.max_bytes {
            return Err(std::io::Error::other(format!(
                "workspace archive exceeds the {} byte cap",
                self.max_bytes
            )));
        }
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        self.len += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Pack a session workspace root (`repo/` + `baseline-git/`) into a gzip'd
/// tar held in memory. Test/fixture-sized use only — the production transport
/// is `pack_workspace_to_file`, which never buffers the archive in RAM.
pub fn pack_workspace(session_root: &Path) -> Result<PackedArchive, WorkspaceError> {
    let bytes = write_tar_gz(session_root, Vec::new())?;
    let sha256 = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
    let len = bytes.len() as u64;
    Ok(PackedArchive { bytes, sha256, len })
}

/// Pack a session workspace root STREAMING to `dest` (`GzEncoder<File>` — the
/// archive never lives in RAM), digesting as it writes and failing cleanly if
/// the compressed size would exceed `max_bytes`. On any error the partial
/// file is removed, so an over-cap or torn archive can never be served.
pub fn pack_workspace_to_file(
    session_root: &Path,
    dest: &Path,
    max_bytes: u64,
) -> Result<StoredArchive, WorkspaceError> {
    let file = std::fs::File::create(dest)
        .map_err(|e| WorkspaceError::Invalid(format!("create {}: {e}", dest.display())))?;
    let sink = HashingWriter {
        inner: std::io::BufWriter::new(file),
        hasher: Sha256::new(),
        len: 0,
        max_bytes,
    };
    let result = write_tar_gz(session_root, sink).and_then(|mut sink| {
        std::io::Write::flush(&mut sink)
            .map_err(|e| WorkspaceError::Invalid(format!("flush {}: {e}", dest.display())))?;
        Ok(sink)
    });
    let sink = match result {
        Ok(sink) => sink,
        Err(e) => {
            let _ = std::fs::remove_file(dest);
            return Err(e);
        }
    };
    let sha256 = format!("sha256:{}", hex::encode(sink.hasher.finalize()));
    Ok(StoredArchive {
        path: dest.to_path_buf(),
        sha256,
        len: sink.len,
    })
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
    // Fresh-destination precondition (fail-closed): the two-phase containment
    // assumes the file/dir phase writes into a symlink-free tree. A re-run over
    // a DIRTY dest — e.g. an init container re-executing on a Pod restart, where
    // the runner may have planted symlinks into the surviving emptyDir — must
    // not let phase 1 follow a stale link out of the root. Clear FIRST (which
    // refuses a symlinked `dest` itself, so we never `create_dir_all` onto or
    // `canonicalize` through a symlink to outside), THEN ensure a real dir.
    clear_dir_contents(dest)
        .map_err(|e| WorkspaceError::Invalid(format!("clear dest {}: {e}", dest.display())))?;
    std::fs::create_dir_all(dest)?;
    let canon_dest = std::fs::canonicalize(dest)?;
    let gz = GzDecoder::new(bytes);
    let mut archive = tar::Archive::new(gz);
    archive.set_preserve_permissions(false);
    archive.set_preserve_mtime(false);

    let mut written: u64 = 0;
    let mut total: u64 = 0;
    // Symlinks are DEFERRED to a second phase. A symlink target can route
    // through OTHER symlinks, which no lexical/depth analysis can resolve —
    // only the kernel can. So we extract every real file/dir first (a
    // dependency-free, symlink-free tree), then create the symlinks and
    // validate each with `canonicalize`, which resolves the FULL chain and is
    // the sole containment authority. See `place_symlinks`.
    let mut deferred: Vec<(PathBuf, PathBuf)> = Vec::new();
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
        // Hardlinks never cross this transport — a distinct escape class from
        // an in-tree symlink, refused unconditionally.
        if etype.is_hard_link() {
            return Err(WorkspaceError::Invalid(format!(
                "archive contains a hard-link entry ({}) — refused",
                path.display()
            )));
        }
        if etype.is_symlink() {
            let target = entry
                .link_name()
                .map_err(|e| WorkspaceError::Invalid(format!("symlink target read: {e}")))?
                .ok_or_else(|| {
                    WorkspaceError::Invalid(format!("symlink '{}' has no target", path.display()))
                })?
                .into_owned();
            deferred.push((safe, target));
            continue;
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

    written += place_symlinks(&canon_dest, &deferred);
    Ok(written)
}

/// Create the deferred symlink entries under `canon_dest`, then keep only
/// those that resolve INSIDE the root. Two phases matter:
///
/// - Create-time: the link's parent must already exist (from the file/dir
///   phase) AND canonicalize inside the root. We never `create_dir_all`
///   through an unvalidated path, so creation can't write outside the root.
/// - Validate-time (after all links exist, so chains resolve): `canonicalize`
///   each link — the kernel follows the entire target chain, including symlink
///   components a lexical check would miss. Anything resolving outside the
///   root, or dangling, is removed. `canonicalize` is the ONLY containment
///   judge; there is no hand-rolled path arithmetic.
///
/// Returns the count of symlinks kept.
fn place_symlinks(canon_dest: &Path, deferred: &[(PathBuf, PathBuf)]) -> u64 {
    let mut created: Vec<PathBuf> = Vec::new();
    for (safe, target) in deferred {
        let Some(parent) = safe.parent() else {
            continue;
        };
        if !parent.exists() {
            continue; // no dir entry shipped the parent → drop
        }
        match std::fs::canonicalize(parent) {
            Ok(cp) if cp.starts_with(canon_dest) => {}
            _ => continue, // parent missing or escapes → drop, never create through it
        }
        if create_symlink(target, safe).is_ok() {
            created.push(safe.clone());
        }
    }
    let mut kept = 0u64;
    for safe in created {
        match std::fs::canonicalize(&safe) {
            Ok(real) if real.starts_with(canon_dest) => kept += 1,
            _ => {
                // Escapes the root, or dangling — the kernel says so; drop it.
                std::fs::remove_file(&safe).ok();
            }
        }
    }
    kept
}

/// Remove every entry INSIDE `dir` (not `dir` itself — it may be a mount
/// point), deleting a symlink as a link rather than following it to its
/// target. Fail-closed: any error propagates so a caller never proceeds over
/// residual state. Used to enforce the fresh-destination precondition of the
/// extractor and the in-pod copy on a lifecycle replay.
pub fn clear_dir_contents(dir: &Path) -> std::io::Result<()> {
    // Trusted-caller contract: `dir` is a caller-controlled path whose
    // ancestors are not attacker-symlinks. In production this holds — `dir` is
    // a fixed pod-spec mount (`/workspace`, `/collector/…`) the runner cannot
    // re-point. The guard below refuses a `dir` whose FINAL component is a
    // symlink; it does NOT resolve a symlinked ANCESTOR or a trailing-slash
    // spelling, and it is not TOCTOU-safe (Codex batch-3v5). Fully symlink-safe
    // extraction against an attacker-controlled destination path requires
    // kernel-enforced resolution (`openat2 RESOLVE_IN_ROOT` on Linux, or the
    // `cap-std`/`openat` crates) — tracked as a follow-up; not production-
    // reachable today.
    match std::fs::symlink_metadata(dir) {
        Ok(m) if m.file_type().is_symlink() => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "refusing to clear a symlinked directory",
            ));
        }
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    }
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        // symlink_metadata: never follow — a symlinked dir is unlinked, not
        // recursed into (which would delete its target's contents).
        if std::fs::symlink_metadata(&path)?.is_dir() {
            std::fs::remove_dir_all(&path)?;
        } else {
            std::fs::remove_file(&path)?;
        }
    }
    Ok(())
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

#[cfg(unix)]
fn create_symlink(target: &Path, at: &Path) -> Result<(), WorkspaceError> {
    std::os::unix::fs::symlink(target, at)
        .map_err(|e| WorkspaceError::Invalid(format!("create symlink {}: {e}", at.display())))
}

#[cfg(not(unix))]
fn create_symlink(_target: &Path, at: &Path) -> Result<(), WorkspaceError> {
    Err(WorkspaceError::Invalid(format!(
        "symlink extraction is unsupported on this platform ({})",
        at.display()
    )))
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
    fn pack_to_file_streams_and_matches_in_memory_pack() {
        // The streaming packer must produce byte-identical output (same
        // digest/len) to the in-memory one — one tar-assembly core, two sinks.
        let tmp = std::env::temp_dir().join(format!("fbx-arch-{}", Uuid::now_v7()));
        let root = tmp.join("ws");
        let repo = root.join("repo");
        std::fs::create_dir_all(repo.join(".git")).unwrap();
        std::fs::write(repo.join("a.txt"), "hello\n").unwrap();
        std::fs::write(repo.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
        std::fs::create_dir_all(root.join(crate::BASELINE_DIR)).unwrap();
        std::fs::write(root.join(crate::BASELINE_DIR).join("HEAD"), "ref: x\n").unwrap();

        let in_mem = pack_workspace(&root).unwrap();
        let dest = tmp.join("archives").join("s.tar.gz");
        std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
        let stored = pack_workspace_to_file(&root, &dest, u64::MAX).unwrap();

        assert_eq!(stored.sha256, in_mem.sha256);
        assert_eq!(stored.len, in_mem.len);
        let on_disk = std::fs::read(&dest).unwrap();
        assert_eq!(on_disk.len() as u64, stored.len);
        verify_archive(&on_disk, stored.len, &stored.sha256).unwrap();

        // And it still unpacks.
        let out = tmp.join("out");
        unpack_archive(&on_disk, &out, 100 * 1024 * 1024).unwrap();
        assert_eq!(
            std::fs::read_to_string(out.join("repo/a.txt")).unwrap(),
            "hello\n"
        );
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn pack_to_file_enforces_max_bytes_and_removes_partial() {
        // The cap fails the pack CLEANLY (a clear error, no partial archive
        // left to be served) — the run dies at zero model spend.
        let tmp = std::env::temp_dir().join(format!("fbx-arch-{}", Uuid::now_v7()));
        let root = tmp.join("ws");
        let repo = root.join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        std::fs::write(repo.join("big.bin"), vec![7u8; 256 * 1024]).unwrap();

        let dest = tmp.join("archives").join("s.tar.gz");
        std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
        let err = pack_workspace_to_file(&root, &dest, 64).unwrap_err();
        assert!(
            err.to_string().contains("64"),
            "error must name the cap: {err}"
        );
        assert!(
            !dest.exists(),
            "a partial over-cap archive must not be left behind"
        );
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn safe_join_rejects_escape_and_accepts_normal() {
        // The tar builder sanitizes `..` at append time, so the escape defense
        // is `safe_join` (a purely lexical guard applied to EVERY entry path,
        // whatever produced the tar). Test it directly against the classic
        // escapes an adversarial archive would carry.
        let base = Path::new("/data/ws");
        for bad in [
            "../escape.txt",
            "a/../../etc/passwd",
            "/etc/passwd",
            "/../x",
        ] {
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
    fn unpack_drops_absolute_symlink() {
        // An absolute-target symlink resolves outside the root; `canonicalize`
        // says so, and it is DROPPED (the rest of the archive still extracts).
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
        assert!(unpack_archive(&bytes, &tmp, 1024 * 1024).is_ok());
        assert!(
            std::fs::symlink_metadata(tmp.join("link")).is_err(),
            "absolute symlink must be dropped, not created"
        );
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

    /// H4: a repo with a tracked in-tree relative symlink (monorepos,
    /// dotfiles) must round-trip as a REAL symlink — Docker runs it fine, so
    /// the K8s provider must too. `materialize_git` does a real checkout, so
    /// these are common.
    #[cfg(unix)]
    #[test]
    fn unpack_creates_intree_relative_symlink() {
        let tmp = std::env::temp_dir().join(format!("fbx-arch-symok-{}", Uuid::now_v7()));
        let root = tmp.join("ws");
        let repo = root.join("repo");
        std::fs::create_dir_all(repo.join("src")).unwrap();
        std::fs::write(repo.join("src/a.txt"), "hello\n").unwrap();
        // repo/link -> src/a.txt (relative, resolves inside the tree)
        std::os::unix::fs::symlink("src/a.txt", repo.join("link")).unwrap();

        let packed = pack_workspace(&root).unwrap();
        let dest = tmp.join("out");
        unpack_archive(&packed.bytes, &dest, 100 * 1024 * 1024).unwrap();

        let link = dest.join("repo/link");
        let meta = std::fs::symlink_metadata(&link).unwrap();
        assert!(
            meta.file_type().is_symlink(),
            "link must extract as a symlink"
        );
        assert_eq!(std::fs::read_link(&link).unwrap(), Path::new("src/a.txt"));
        assert_eq!(std::fs::read_to_string(&link).unwrap(), "hello\n");
        std::fs::remove_dir_all(&tmp).ok();
    }

    /// H4 must not open an escape hatch: a symlink whose target leaves the
    /// dest root — through `..` climbs or an absolute path — is dropped, while
    /// a legitimate in-tree link in the SAME archive survives. `canonicalize`
    /// is the judge, so this holds even when the target routes through another
    /// symlink component (Codex batch-3v2 review counterexample:
    /// `pivot -> ..`, `escape -> pivot/..`).
    #[cfg(unix)]
    #[test]
    fn unpack_drops_escaping_symlinks_keeps_good() {
        fn sym(b: &mut tar::Builder<&mut GzEncoder<Vec<u8>>>, path: &str, target: &str) {
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(tar::EntryType::Symlink);
            h.set_size(0);
            h.set_link_name(target).unwrap();
            h.set_cksum();
            b.append_data(&mut h, path, std::io::empty()).unwrap();
        }
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        {
            let mut b = tar::Builder::new(&mut gz);
            let mut d = tar::Header::new_gnu();
            d.set_entry_type(tar::EntryType::Directory);
            d.set_mode(0o755);
            d.set_size(0);
            d.set_cksum();
            b.append_data(&mut d, "repo/", std::io::empty()).unwrap();
            let content = b"hi\n";
            let mut f = tar::Header::new_gnu();
            f.set_entry_type(tar::EntryType::Regular);
            f.set_size(content.len() as u64);
            f.set_cksum();
            b.append_data(&mut f, "repo/good.txt", &content[..])
                .unwrap();
            // Legit in-tree link — must survive.
            sym(&mut b, "repo/good_link", "good.txt");
            // Escapers — must all be dropped.
            sym(&mut b, "repo/abs", "/etc/passwd");
            sym(&mut b, "repo/up", "../../etc/passwd");
            // Symlinked-component escape (the counterexample lexical math misses).
            sym(&mut b, "repo/pivot", "..");
            sym(&mut b, "repo/escape", "pivot/..");
            b.finish().unwrap();
        }
        let bytes = gz.finish().unwrap();
        let tmp = std::env::temp_dir().join(format!("fbx-arch-symbad-{}", Uuid::now_v7()));
        assert!(unpack_archive(&bytes, &tmp, 10 * 1024 * 1024).is_ok());

        assert_eq!(
            std::fs::read_to_string(tmp.join("repo/good_link")).unwrap(),
            "hi\n",
            "legit in-tree symlink must survive"
        );
        for bad in ["repo/abs", "repo/up", "repo/escape"] {
            assert!(
                std::fs::symlink_metadata(tmp.join(bad)).is_err(),
                "escaping symlink {bad} must be dropped"
            );
        }
        std::fs::remove_dir_all(&tmp).ok();
    }

    /// Security regression (Codex, batch-3 review): a symlinked-parent
    /// traversal. Entry 1 makes `repo/a` resolve to dest; entry 2
    /// (`repo/a/root -> ../..`) points above dest; entry 3 writes a file
    /// through it. The two-phase extractor creates files first (so `repo/a`
    /// becomes a real dir and the symlinks collide/drop) and never writes
    /// through a symlink — nothing may land outside dest.
    #[cfg(unix)]
    #[test]
    fn unpack_contains_symlinked_parent_traversal() {
        fn sym(b: &mut tar::Builder<&mut GzEncoder<Vec<u8>>>, path: &str, target: &str) {
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(tar::EntryType::Symlink);
            h.set_size(0);
            h.set_link_name(target).unwrap();
            h.set_cksum();
            b.append_data(&mut h, path, std::io::empty()).unwrap();
        }
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        {
            let mut b = tar::Builder::new(&mut gz);
            let mut d = tar::Header::new_gnu();
            d.set_entry_type(tar::EntryType::Directory);
            d.set_mode(0o755);
            d.set_size(0);
            d.set_cksum();
            b.append_data(&mut d, "repo/", std::io::empty()).unwrap();
            sym(&mut b, "repo/a", "..");
            sym(&mut b, "repo/a/root", "../..");
            let content = b"PWNED";
            let mut f = tar::Header::new_gnu();
            f.set_entry_type(tar::EntryType::Regular);
            f.set_size(content.len() as u64);
            f.set_cksum();
            b.append_data(&mut f, "repo/a/root/workspace/pwn", &content[..])
                .unwrap();
            b.finish().unwrap();
        }
        let bytes = gz.finish().unwrap();

        let base = std::env::temp_dir().join(format!("fbx-arch-esc-{}", Uuid::now_v7()));
        // Nest dest so that if the escape DID fire (pre-fix), the written file
        // lands under `base` and cleanup still removes it.
        let dest = base.join("l1").join("l2").join("root");
        std::fs::create_dir_all(&dest).unwrap();

        let res = unpack_archive(&bytes, &dest, 10 * 1024 * 1024);

        // No `pwn` may exist anywhere under base OUTSIDE dest.
        let mut escaped = false;
        for entry in walkdir(&base) {
            if entry.file_name().and_then(|n| n.to_str()) == Some("pwn")
                && !entry.starts_with(&dest)
            {
                escaped = true;
            }
        }
        assert!(!escaped, "file escaped dest via symlinked parent");
        assert!(res.is_ok(), "extraction stays contained (drops the links)");
        std::fs::remove_dir_all(&base).ok();
    }

    // Tiny recursive lister for the escape test (no dev-dep for one test).
    fn walkdir(root: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let Ok(rd) = std::fs::read_dir(&dir) else {
                continue;
            };
            for e in rd.flatten() {
                let p = e.path();
                // symlink_metadata: don't follow (an escaping symlink dir would
                // otherwise recurse out of the tree).
                if let Ok(m) = std::fs::symlink_metadata(&p) {
                    if m.is_dir() {
                        stack.push(p.clone());
                    }
                }
                out.push(p);
            }
        }
        out
    }

    /// Codex batch-3v3 finding 2: unpack over a DIRTY dest (an init container
    /// re-executing over the surviving emptyDir) must clear it first, so a
    /// runner-planted `repo -> outside` symlink can't make the file phase
    /// write through it.
    #[cfg(unix)]
    #[test]
    fn unpack_clears_stale_destination_symlink() {
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        {
            let mut b = tar::Builder::new(&mut gz);
            let mut d = tar::Header::new_gnu();
            d.set_entry_type(tar::EntryType::Directory);
            d.set_mode(0o755);
            d.set_size(0);
            d.set_cksum();
            b.append_data(&mut d, "repo/", std::io::empty()).unwrap();
            let content = b"fresh";
            let mut f = tar::Header::new_gnu();
            f.set_entry_type(tar::EntryType::Regular);
            f.set_size(content.len() as u64);
            f.set_cksum();
            b.append_data(&mut f, "repo/pwn", &content[..]).unwrap();
            b.finish().unwrap();
        }
        let bytes = gz.finish().unwrap();

        let base = std::env::temp_dir().join(format!("fbx-arch-stale-{}", Uuid::now_v7()));
        let outside = base.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("canary"), "ORIGINAL\n").unwrap();
        let dest = base.join("dest");
        std::fs::create_dir_all(&dest).unwrap();
        // Runner planted a symlink where a real dir entry will land.
        std::os::unix::fs::symlink(&outside, dest.join("repo")).unwrap();

        unpack_archive(&bytes, &dest, 10 * 1024 * 1024).unwrap();

        assert!(
            dest.join("repo/pwn").is_file(),
            "fresh file lands inside dest"
        );
        assert!(
            !outside.join("pwn").exists(),
            "must not write through the stale destination symlink"
        );
        assert_eq!(
            std::fs::read_to_string(outside.join("canary")).unwrap(),
            "ORIGINAL\n"
        );
        std::fs::remove_dir_all(&base).ok();
    }

    /// Codex batch-3v4 finding (e): a `dest` that is itself a symlink to an
    /// outside directory must be REFUSED, never cleared/extracted through — a
    /// symlinked dest would otherwise delete the target's contents and treat
    /// the outside dir as the root.
    #[cfg(unix)]
    #[test]
    fn unpack_refuses_symlinked_dest() {
        let base = std::env::temp_dir().join(format!("fbx-arch-symdest-{}", Uuid::now_v7()));
        let outside = base.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("canary"), "ORIGINAL\n").unwrap();
        let dest = base.join("dest");
        std::os::unix::fs::symlink(&outside, &dest).unwrap();

        // Any archive; it must not get far.
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        {
            let mut b = tar::Builder::new(&mut gz);
            b.append_data(
                &mut {
                    let mut h = tar::Header::new_gnu();
                    h.set_entry_type(tar::EntryType::Regular);
                    h.set_size(1);
                    h.set_cksum();
                    h
                },
                "x",
                &b"y"[..],
            )
            .unwrap();
            b.finish().unwrap();
        }
        let bytes = gz.finish().unwrap();

        assert!(
            unpack_archive(&bytes, &dest, 1024 * 1024).is_err(),
            "a symlinked dest must be refused"
        );
        assert!(outside.join("canary").exists(), "outside must be untouched");
        assert!(!outside.join("x").exists());
        std::fs::remove_dir_all(&base).ok();
    }

    /// Hardlinks remain refused unconditionally — the transport never needs
    /// one and a hardlink is a distinct escape class from an in-tree symlink.
    #[test]
    fn unpack_still_rejects_hardlink() {
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        {
            let mut b = tar::Builder::new(&mut gz);
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Link);
            header.set_size(0);
            header.set_link_name("repo/a.txt").unwrap();
            header.set_cksum();
            b.append_data(&mut header, "repo/hard", std::io::empty())
                .unwrap();
            b.finish().unwrap();
        }
        let bytes = gz.finish().unwrap();
        let tmp = std::env::temp_dir().join(format!("fbx-arch-hard-{}", Uuid::now_v7()));
        assert!(unpack_archive(&bytes, &tmp, 1024 * 1024).is_err());
        std::fs::remove_dir_all(&tmp).ok();
    }
}
