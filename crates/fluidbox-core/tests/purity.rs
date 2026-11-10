//! `fluidbox-core` is the pure domain: no I/O. Two things keep that true.
//!
//! Cargo does half the work for free — a crate cannot `use` what its manifest
//! does not declare — so the first test keeps I/O-capable crates out of the
//! manifest. (It once declared `tokio` and `futures` without using either, which
//! left `tokio::fs` and `tokio::net` one line away from the policy engine.)
//!
//! `std` is the half Cargo cannot see: `std::fs`, `std::process`, `std::env` and
//! the socket types resolve in every crate without being declared. The second
//! test scans for them.
//!
//! Reading the clock is not policed here — `EventEnvelope::new` stamps
//! `Utc::now()` — only reaching outside the process is.

use std::fs;
use std::path::{Path, PathBuf};

/// Crates that exist to do I/O. Declaring one here makes it one `use` away.
const IO_CRATES: &[&str] = &[
    "async-std",
    "aws-config",
    "aws-sdk-kms",
    "axum",
    "bollard",
    "dotenvy",
    "hyper",
    "kube",
    "reqwest",
    "smol",
    "sqlx",
    "tokio",
    "tokio-stream",
    "tower-http",
];

/// Paths that reach outside the process. Matched against code only — comments
/// and `#[cfg(test)]` modules are stripped first, so prose that merely mentions
/// `std::fs` cannot trip it.
const IO_PATHS: &str = r"\b(fs|process|env)::|\bstd::os::|\btokio::|\b(TcpStream|TcpListener|UdpSocket|UnixStream|ToSocketAddrs)\b";

/// Names declared under `[dependencies]` — NOT `[dev-dependencies]`: tests may
/// use whatever they like.
fn dependencies(manifest: &str) -> Vec<String> {
    let mut inside = false;
    let mut names = Vec::new();
    for line in manifest.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            inside = line == "[dependencies]";
        } else if inside {
            let name: String = line
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
                .collect();
            if !name.is_empty() {
                names.push(name);
            }
        }
    }
    names
}

/// The file's production code: `//` comments cut, top-level `#[cfg(test)]`
/// modules dropped. Line numbers are preserved so a hit can be reported.
fn production_code(source: &str) -> Vec<(usize, String)> {
    let lines: Vec<&str> = source.lines().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let is_test_module = lines[i] == "#[cfg(test)]"
            && lines
                .get(i + 1)
                .is_some_and(|next| next.starts_with("mod ") && next.ends_with('{'));
        if is_test_module {
            while i < lines.len() && lines[i] != "}" {
                i += 1;
            }
        } else {
            let code = lines[i].split("//").next().unwrap_or("");
            out.push((i + 1, code.to_string()));
        }
        i += 1;
    }
    out
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("a readable source directory") {
        let path = entry.expect("a readable entry").path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn core_declares_no_io_crate() {
    let manifest = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
        .expect("fluidbox-core's manifest");
    let deps = dependencies(&manifest);
    assert!(
        deps.iter().any(|d| d == "serde"),
        "parsed no dependencies — the manifest shape changed and this guard went blind"
    );
    let offenders: Vec<_> = deps
        .iter()
        .filter(|d| IO_CRATES.contains(&d.as_str()))
        .collect();
    assert!(
        offenders.is_empty(),
        "fluidbox-core is the pure domain and must not depend on {offenders:?}. \
         I/O belongs in fluidbox-db, fluidbox-provider or fluidbox-server; hand core \
         the data, not the means of fetching it."
    );
}

#[test]
fn core_source_reaches_for_no_io() {
    let io = regex::Regex::new(IO_PATHS).expect("a valid pattern");
    let mut files = Vec::new();
    rust_files(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut files,
    );
    files.sort();
    assert!(
        files.len() > 5,
        "found only {} source files — this guard is looking in the wrong place",
        files.len()
    );

    let mut hits = Vec::new();
    for path in &files {
        let text = fs::read_to_string(path).expect("a readable source file");
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        for (line, code) in production_code(&text) {
            if let Some(m) = io.find(&code) {
                hits.push(format!("{name}:{line}: `{}`", m.as_str()));
            }
        }
    }
    assert!(
        hits.is_empty(),
        "fluidbox-core must not perform I/O:\n  {}\n",
        hits.join("\n  ")
    );
}
