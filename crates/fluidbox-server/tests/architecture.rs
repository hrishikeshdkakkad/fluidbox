//! Architecture fitness functions.
//!
//! Structural facts about the workspace that nothing else checks. Cargo already
//! refuses an undeclared dependency and a dependency cycle, so the crate graph is
//! deliberately NOT restated here — a guard the toolchain already provides is
//! noise, and noise gets deleted.
//!
//! What lives here is what the toolchain cannot see:
//!
//! * file size, against a shrink-only ledger;
//! * `fluidbox-db`'s crate root staying wiring-only;
//! * the audited RLS bypass being opened only where it is inventoried;
//! * `fluidbox-obs` staying a leaf (the one reverse edge Cargo would accept).
//!
//! `fluidbox-core`'s purity is guarded next to the crate it describes, in
//! `crates/fluidbox-core/tests/purity.rs`.
//!
//! These read source files; they need no database and no network.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the workspace root exists")
}

fn read(rel: &str) -> String {
    fs::read_to_string(repo_root().join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

// ─── Size budget ────────────────────────────────────────────────────────────

/// A source file with no ledger entry may be at most this many lines.
///
/// Physical lines, inline tests included — exactly what `wc -l` prints, so
/// anyone can check a number here without a parser. The project states no size
/// standard of its own; this one is a starting point, not a finding.
const BUDGET: usize = 1500;

/// How far a ledgered file may shrink before its cap must be lowered to match.
const SLACK: usize = 100;

/// Where the budget applies: `(directory, extensions)`.
const SCOPE: &[(&str, &[&str])] = &[
    ("crates", &["rs"]),
    ("apps/web/app", &["ts", "tsx"]),
    ("images", &["mjs"]),
];

/// Directories never descended into.
const SKIP_DIRS: &[&str] = &["node_modules", "target", "generated", ".next"];

/// The debt ledger: every file over [`BUDGET`], capped at the size it had when
/// it was entered. Sorted by path, one entry per line, so concurrent changes
/// merge cleanly.
///
/// This list is meant to get SHORTER. Raising a cap is a decision — make it in
/// review, with a reason, not to get a build green.
const LEDGER: &[(&str, usize)] = &[
    // One ~1,780-line component function.
    ("apps/web/app/components/RunComposer.tsx", 2090),
    ("crates/fluidbox-core/src/network.rs", 2149),
    ("crates/fluidbox-core/src/policy.rs", 2832),
    ("crates/fluidbox-db/src/governance.rs", 1761),
    ("crates/fluidbox-db/src/identity.rs", 4435),
    // All of it is the single `mod tests`; the production half now lives in the
    // domain modules beside it. Splitting the tests by domain is the DEFERRED
    // half of that change, and it has a precondition: three checks read THIS
    // file by path and assert something is ABSENT or appears EXACTLY ONCE —
    // `tenant_less_scans_go_through_the_scoped_helpers`,
    // `conversion_is_only_ever_invoked_rls_bound`, and the fixture-drift grep in
    // `scripts/db-clean-tests.sh`. Move a test out before widening them to every
    // test file and they keep passing while guarding nothing.
    ("crates/fluidbox-db/src/lib.rs", 10938),
    ("crates/fluidbox-provider-k8s/src/lib.rs", 1655),
    ("crates/fluidbox-server/src/admin_orgs.rs", 1664),
    ("crates/fluidbox-server/src/api.rs", 2136),
    ("crates/fluidbox-server/src/auth.rs", 1622),
    ("crates/fluidbox-server/src/bindings.rs", 2039),
    ("crates/fluidbox-server/src/broker.rs", 5317),
    ("crates/fluidbox-server/src/config.rs", 1940),
    ("crates/fluidbox-server/src/connectors/github.rs", 1917),
    ("crates/fluidbox-server/src/facade.rs", 2104),
    ("crates/fluidbox-server/src/github_app.rs", 1682),
    ("crates/fluidbox-server/src/governor.rs", 2427),
    ("crates/fluidbox-server/src/internal.rs", 2685),
    ("crates/fluidbox-server/src/login.rs", 2918),
    ("crates/fluidbox-server/src/oauth.rs", 3916),
    ("crates/fluidbox-server/src/orchestrator.rs", 2843),
    ("crates/fluidbox-server/src/recipes.rs", 2020),
    ("crates/fluidbox-server/src/triggers.rs", 2116),
    ("crates/fluidbox-server/src/workers.rs", 1575),
    ("crates/fluidbox-workspace/src/store.rs", 2113),
];

/// The ratchet: does a file of `lines` lines pass, given its ledger cap (if any)?
///
/// This function IS the policy, and it is the part worth arguing about. As
/// written it is a middle setting:
///
/// * an unledgered file must fit the budget;
/// * a ledgered file may never exceed its cap — growth has to raise the cap,
///   which puts the decision in the diff where a reviewer sees it;
/// * a file that shrinks by more than [`SLACK`] must bank the gain (lower the
///   cap), so paid-off debt cannot be quietly re-spent;
/// * a file back under the budget must leave the ledger entirely.
///
/// The stricter setting (`SLACK = 0`) banks every line but makes each change to
/// a ledgered file also touch the ledger. The looser one (no slack check) never
/// nags, and leaves every shrink as licence to grow back.
fn verdict(lines: usize, cap: Option<usize>) -> Result<(), String> {
    match cap {
        None if lines > BUDGET => Err(format!(
            "is {lines} lines, over the {BUDGET}-line budget — split it, or enter it in LEDGER at {lines}"
        )),
        None => Ok(()),
        Some(_) if lines <= BUDGET => Err(format!(
            "is {lines} lines, back under the budget — delete its LEDGER entry"
        )),
        Some(cap) if lines > cap => Err(format!(
            "grew to {lines} lines, past its cap of {cap} — shrink it, or raise the cap in review"
        )),
        Some(cap) if cap - lines > SLACK => Err(format!(
            "shrank to {lines} lines — lower its LEDGER cap from {cap} to {lines}"
        )),
        Some(_) => Ok(()),
    }
}

/// The ratchet's five outcomes, pinned — so a change to the policy above is a
/// change to this table, not an accident.
#[test]
fn the_ratchet_has_five_outcomes() {
    let over = BUDGET + 500;
    assert!(verdict(BUDGET, None).is_ok(), "at the budget, unledgered");
    assert!(
        verdict(BUDGET + 1, None).is_err(),
        "over the budget, unledgered"
    );
    assert!(verdict(over, Some(over)).is_ok(), "ledgered, at its cap");
    assert!(
        verdict(over + 1, Some(over)).is_err(),
        "ledgered, grown past its cap"
    );
    assert!(
        verdict(over - SLACK, Some(over)).is_ok(),
        "shrunk within the slack"
    );
    assert!(
        verdict(over - SLACK - 1, Some(over)).is_err(),
        "shrunk past the slack: bank it"
    );
    assert!(
        verdict(BUDGET, Some(over)).is_err(),
        "paid off: leave the ledger"
    );
}

fn collect(dir: &Path, exts: &[&str], root: &Path, out: &mut BTreeMap<String, usize>) {
    let mut entries: Vec<_> = fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()))
        .map(|e| e.expect("a readable directory entry").path())
        .collect();
    entries.sort();
    for path in entries {
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if path.is_dir() {
            if !SKIP_DIRS.contains(&name) {
                collect(&path, exts, root, out);
            }
        } else if path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| exts.contains(&e))
        {
            let rel = path
                .strip_prefix(root)
                .expect("a path under the workspace root")
                .to_string_lossy()
                .replace('\\', "/");
            let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {rel}: {e}"));
            out.insert(rel, text.lines().count());
        }
    }
}

#[test]
fn source_files_fit_the_size_budget() {
    let root = repo_root();
    let mut sizes = BTreeMap::new();
    for (dir, exts) in SCOPE {
        collect(&root.join(dir), exts, &root, &mut sizes);
    }
    assert!(
        sizes.len() > 100,
        "the scan found only {} files — SCOPE no longer points at the source tree",
        sizes.len()
    );

    let caps: BTreeMap<&str, usize> = LEDGER.iter().copied().collect();
    let mut problems = Vec::new();

    for pair in LEDGER.windows(2) {
        if pair[0].0 >= pair[1].0 {
            problems.push(format!(
                "LEDGER must stay sorted and unique: `{}` then `{}`",
                pair[0].0, pair[1].0
            ));
        }
    }
    for (path, _) in LEDGER {
        if !sizes.contains_key(*path) {
            problems.push(format!("{path} no longer exists — delete its LEDGER entry"));
        }
    }
    for (path, lines) in &sizes {
        if let Err(why) = verdict(*lines, caps.get(path.as_str()).copied()) {
            problems.push(format!("{path} {why}"));
        }
    }

    assert!(
        problems.is_empty(),
        "size budget (crates/fluidbox-server/tests/architecture.rs):\n  {}\n",
        problems.join("\n  ")
    );
}

// ─── fluidbox-db: the crate root is wiring only ─────────────────────────────

fn is_module_decl(line: &str) -> bool {
    line.strip_prefix("pub mod ")
        .or_else(|| line.strip_prefix("mod "))
        .and_then(|rest| rest.strip_suffix(';'))
        .is_some_and(|name| name.chars().all(|c| c.is_ascii_lowercase() || c == '_'))
}

/// `fluidbox-db/src/lib.rs` held 7,870 lines of production code in 31 drifting
/// sections until each table family got its own module. Its root is now a table
/// of contents — module declarations and flat re-exports, so `fluidbox_db::x`
/// keeps resolving for every caller — and it must stay one. A function added
/// back to the root is the first step toward the same file.
#[test]
fn db_crate_root_is_wiring_only() {
    let src = read("crates/fluidbox-db/src/lib.rs");
    let mut offenders = Vec::new();
    for (i, line) in src.lines().enumerate() {
        if line.starts_with("mod tests") {
            break; // the test module is the last thing in the root
        }
        let wiring = line.is_empty()
            || line.starts_with("//")
            || line == "#[cfg(test)]"
            || is_module_decl(line)
            || (line.starts_with("pub use ") && line.ends_with("::*;"));
        if !wiring {
            offenders.push(format!("lib.rs:{}: {line}", i + 1));
        }
    }
    assert!(
        offenders.is_empty(),
        "fluidbox-db's crate root declares modules and re-exports them, nothing else. \
         Put this in the module for its table family (or a new one):\n  {}\n",
        offenders.join("\n  ")
    );
}

// ─── fluidbox-db: the audited RLS bypass ────────────────────────────────────

/// Every production function in `fluidbox-db` that opens `worker_tx` — the
/// transaction that sets `fluidbox.bypass` and therefore reads across tenants —
/// outside `system_worker`, which is the bypass's home and may add scans freely.
///
/// This is the inventory in the `system_worker` module docs, made executable.
/// Adding a name here is the review event that documentation asks for: say in
/// the change why the caller has no tenant to scope by.
const BYPASS_CALLERS: &[(&str, &[&str])] = &[
    (
        "connector_oauth.rs",
        &["claim_connector_oauth_flow", "peek_connector_oauth_flow"],
    ),
    (
        "github_app.rs",
        &["claim_github_app_bootstrap", "claim_github_app_flow"],
    ),
    (
        "identity.rs",
        &[
            "active_idp_config",
            "claim_login_flow",
            "claim_pending_switch",
            "create_org",
            "create_org_audited",
            "get_org_by_slug",
            "insert_audit_standalone",
            "list_orgs",
            "resolve_pat",
            "resolve_web_session",
        ],
    ),
    ("mcp_sessions.rs", &["sweep_orphaned_upstream_sessions"]),
    ("tenants.rs", &["ensure_default_tenant"]),
    (
        "tokens.rs",
        &[
            "extend_session_token",
            "session_for_token",
            "session_for_token_incl_revoked",
            "subscription_for_token",
        ],
    ),
];

/// A file's production code: `//` comments cut, top-level `#[cfg(test)]`
/// modules dropped.
fn production_lines(source: &str) -> Vec<&str> {
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
            out.push(lines[i].split("//").next().unwrap_or(""));
        }
        i += 1;
    }
    out
}

/// The name a `fn` line declares, at any indentation and visibility.
fn declared_fn(line: &str) -> Option<&str> {
    let (_, rest) = line.split_once("fn ")?;
    let before = line.split("fn ").next().unwrap_or("").trim();
    let is_decl = before
        .split_whitespace()
        .all(|w| w.starts_with("pub") || w == "async" || w == "const" || w == "unsafe");
    let end = rest.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))?;
    (is_decl && end > 0).then(|| &rest[..end])
}

#[test]
fn the_rls_bypass_is_opened_only_where_inventoried() {
    let dir = repo_root().join("crates/fluidbox-db/src");
    let mut found: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut files = 0;
    for entry in fs::read_dir(&dir).expect("fluidbox-db/src") {
        let path = entry.expect("a readable entry").path();
        let name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        if !name.ends_with(".rs") || name == "system_worker.rs" {
            continue;
        }
        files += 1;
        let text = fs::read_to_string(&path).expect("a readable source file");
        let mut current = String::new();
        for line in production_lines(&text) {
            if let Some(f) = declared_fn(line) {
                current = f.to_string();
            }
            if line.contains("worker_tx(") && current != "worker_tx" {
                found.entry(name.clone()).or_default().push(current.clone());
            }
        }
    }
    assert!(
        files > 20,
        "scanned only {files} files — this guard is looking in the wrong place"
    );

    let mut problems = Vec::new();
    for (file, expected) in BYPASS_CALLERS {
        let mut got = found.remove(*file).unwrap_or_default();
        got.sort();
        got.dedup();
        for f in &got {
            if !expected.contains(&f.as_str()) {
                problems.push(format!(
                    "{file}: `{f}` opens the bypass and is not inventoried"
                ));
            }
        }
        for f in *expected {
            if !got.iter().any(|g| g == f) {
                problems.push(format!(
                    "{file}: `{f}` is inventoried but no longer opens the bypass — remove it"
                ));
            }
        }
    }
    for (file, fns) in found {
        problems.push(format!(
            "{file}: {fns:?} open the bypass from a module with no inventory"
        ));
    }
    assert!(
        problems.is_empty(),
        "`worker_tx` reads across tenants. Every caller outside `system_worker` is listed in \
         BYPASS_CALLERS and in the `system_worker` module docs; keep both in step:\n  {}\n",
        problems.join("\n  ")
    );
}

// ─── Leaf crates ────────────────────────────────────────────────────────────

/// Names declared under one `[section]` of a Cargo manifest.
fn declared(manifest: &str, section: &str) -> Vec<String> {
    let mut inside = false;
    let mut names = Vec::new();
    for line in manifest.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            inside = line == section;
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

/// `fluidbox-obs` is a leaf so that every crate — `fluidbox-core` included — can
/// log through it. Cargo enforces most of the graph by refusing cycles, but not
/// this edge: `fluidbox-core` only DEV-depends on `fluidbox-obs`, and Cargo
/// permits a cycle through a dev-dependency, so `obs -> core` would compile.
#[test]
fn obs_stays_a_leaf_crate() {
    let deps = declared(&read("crates/fluidbox-obs/Cargo.toml"), "[dependencies]");
    assert!(
        !deps.is_empty(),
        "parsed no dependencies from fluidbox-obs — the manifest shape changed"
    );
    let workspace: Vec<_> = deps
        .iter()
        .filter(|d| d.starts_with("fluidbox-") || d.as_str() == "workspaced")
        .collect();
    assert!(
        workspace.is_empty(),
        "fluidbox-obs must depend on no workspace crate, found {workspace:?}"
    );
}
