//! Test-only support shared by EVERY module's database tests.
//!
//! `cargo test` runs a crate's tests concurrently against ONE database, and each
//! `system_worker` sweep is a tenant-less GLOBAL scan (that is the production
//! contract: one worker tick covers every tenant). So one test's scan also sees,
//! converts and claims the rows of every test running beside it. The failure
//! modes and their cure are written up at the top of the `lib.rs` test module;
//! this file holds the two pieces every module needs, because the crate is split
//! one module per table family and a guard visible only inside `lib.rs` simply
//! did not apply to tests that live elsewhere.
//!
//! That is not hypothetical. `mcp_sessions`' two sweeper tests sat outside the
//! guard: one swept the whole table with `limit 200` while the other was between
//! making its rows scannable and asserting that a `limit 1` pass left two of
//! them, and CI failed with `left: 0`.

/// Held from the moment a test's rows become scannable until its own scan has
/// run and been asserted on. Tests are otherwise concurrent; only that window is
/// mutually exclusive, which is exactly the condition under which a global scan
/// can be reasoned about locally.
pub(crate) static GLOBAL_SCAN: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Source guard: a tenant-less scan must never be called bare from a test,
/// because a bare call asserts about every OTHER test's rows and races them for
/// their own. It reads EVERY source file in the crate rather than one, so a scan
/// test added to any module is held to the same rule.
///
/// Each scan may appear exactly twice: its definition and one guarded call site.
/// Needles are assembled from two halves so this file is not itself a match.
#[test]
fn tenant_less_scans_go_through_the_scoped_helpers() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut sources = Vec::new();
    let mut stack = vec![dir];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).expect("read src dir") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let text = std::fs::read_to_string(&path).expect("read source");
                sources.push((path, text));
            }
        }
    }
    assert!(
        sources.len() > 10,
        "found only {} source files — the guard is not reading the crate",
        sources.len()
    );

    for (needle, site) in [
        (
            concat!("sweep_expired_llm", "_reservations("),
            "lib.rs `sweep_reservations`",
        ),
        (
            concat!("sweep_stale_execution", "_claims("),
            "lib.rs `sweep_stale_claims`",
        ),
        (
            concat!("claim_due", "_deliveries("),
            "lib.rs `claim_deliveries`",
        ),
        (
            concat!("expired_pending", "_approvals("),
            "the single containment-only caller in lib.rs",
        ),
        (
            concat!("sweep_orphaned", "_upstream_sessions("),
            "mcp_sessions.rs `sweep_upstream`",
        ),
    ] {
        let hits: Vec<String> = sources
            .iter()
            .flat_map(|(path, text)| {
                text.lines()
                    .enumerate()
                    .filter(|(_, line)| line.contains(needle))
                    .map(move |(i, _)| {
                        format!("{}:{}", path.file_name().unwrap().to_string_lossy(), i + 1)
                    })
            })
            .collect();
        assert_eq!(
            hits.len(),
            2,
            "`{needle}` must appear exactly twice in fluidbox-db — its definition and \
             {site} — found {}: {hits:?}. Route a new call through that helper and hold \
             GLOBAL_SCAN from the moment your rows become scannable: a bare call counts \
             every other test's rows into your batch and converts/claims them out of theirs.",
            hits.len()
        );
    }
}
