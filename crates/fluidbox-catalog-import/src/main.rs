//! `catalog-import` — the offline connector-catalog importer CLI.
//!
//! Reads a PINNED open-connector checkout's generated catalog JSON
//! (`<src>/catalog/apps/*.json`, produced by `npm run generate:catalog` in that
//! repo — the robust primary path, §5) and writes a deterministic, append-only
//! `connector_catalog` migration of untrusted community-tier reference rows.
//!
//!   just catalog-import --src ../open-connector --sha <commit> \
//!       --out migrations/0010_catalog_import.sql
//!
//! It never fetches open-connector and is not part of the server crate graph.

use anyhow::{bail, Context, Result};
use clap::Parser;
use fluidbox_catalog_import::{emit_migration, transform, OcProvider, HOSTED_MCP};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "catalog-import",
    about = "Regenerate the connector-catalog import migration from a pinned open-connector checkout"
)]
struct Args {
    /// Path to a PINNED open-connector checkout. Must contain catalog/apps/*.json
    /// (run `npm run generate:catalog` in that repo first).
    #[arg(long)]
    src: PathBuf,

    /// Output migration path, e.g. migrations/0010_catalog_import.sql.
    #[arg(long)]
    out: PathBuf,

    /// The pinned open-connector commit SHA — recorded in the migration header
    /// AND every row's provenance (the diff key for a future re-import).
    #[arg(long)]
    sha: String,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let apps = args.src.join("catalog/apps");
    if !apps.is_dir() {
        bail!(
            "{} not found — run `npm run generate:catalog` in the open-connector \
             checkout first (the generated JSON is the primary import path)",
            apps.display()
        );
    }

    let mut providers = Vec::new();
    let mut parse_errors = 0usize;
    let mut entries: Vec<PathBuf> = std::fs::read_dir(&apps)
        .with_context(|| format!("reading {}", apps.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("json"))
        .collect();
    entries.sort(); // stable iteration regardless of filesystem order

    for path in &entries {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        match serde_json::from_str::<OcProvider>(&text) {
            Ok(p) => providers.push(p),
            Err(e) => {
                eprintln!("skip {}: parse error: {e}", path.display());
                parse_errors += 1;
            }
        }
    }

    let result = transform(providers, HOSTED_MCP);
    for d in &result.dropped {
        eprintln!("drop {}: {}", d.service, d.reason);
    }

    if result.rows.is_empty() {
        bail!("no providers survived screening — refusing to write an empty migration");
    }

    let sql = emit_migration(&result.rows, &args.sha);
    std::fs::write(&args.out, &sql).with_context(|| format!("writing {}", args.out.display()))?;

    eprintln!(
        "wrote {} rows to {} ({} dropped, {} parse errors) — pinned {}",
        result.rows.len(),
        args.out.display(),
        result.dropped.len(),
        parse_errors,
        args.sha,
    );
    Ok(())
}
