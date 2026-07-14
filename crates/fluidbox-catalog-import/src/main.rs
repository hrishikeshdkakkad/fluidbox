//! `catalog-import` — the offline connector-catalog importer CLI (plan rev 2).
//!
//! Two sources, one migration, Registry first:
//!   - the official **MCP Registry** (primary; connectable breadth), paged live
//!     from `GET /v0/servers` or read from a captured snapshot for reproducible
//!     generation;
//!   - **open-connector** (supplement; REST-only reference cards) from a pinned
//!     local checkout's generated catalog JSON.
//!
//!   # live Registry only
//!   just catalog-import --registry-url https://registry.modelcontextprotocol.io \
//!       --registry-ref 2026-07-14 --out migrations/0010_catalog_import.sql
//!
//!   # both sources, hermetic Registry snapshot
//!   catalog-import --registry-snapshot registry.json --registry-ref 2026-07-14 \
//!       --open-connector ../open-connector --oc-sha <commit> \
//!       --out migrations/0010_catalog_import.sql
//!
//! It is not part of the server crate graph and never runs at boot/request time.

use anyhow::{bail, Context, Result};
use clap::Parser;
use fluidbox_catalog_import::{
    build, emit_migration, parse_registry_snapshot, OcProvider, Pins, RegistryEntry, RegistryPage,
};
use std::path::{Path, PathBuf};

const DEFAULT_REGISTRY: &str = "https://registry.modelcontextprotocol.io";

#[derive(Parser)]
#[command(
    name = "catalog-import",
    about = "Regenerate the connector-catalog import migration from the MCP Registry (+ open-connector)"
)]
struct Args {
    /// Page the live MCP Registry at this base URL (e.g. the default). Mutually
    /// complementary with --registry-snapshot; if neither is set, no Registry
    /// rows are imported.
    #[arg(long)]
    registry_url: Option<String>,

    /// Read Registry servers from a captured JSON snapshot instead of the
    /// network (a `{servers:[…]}` page, an array of pages, or an array of
    /// server entries). Reproducible + hermetic.
    #[arg(long)]
    registry_snapshot: Option<PathBuf>,

    /// The Registry snapshot ref (final cursor / date) recorded in the header
    /// and every Registry row's provenance. Strongly recommended when importing
    /// Registry rows so the migration is pinned.
    #[arg(long)]
    registry_ref: Option<String>,

    /// Page size when paging the live Registry.
    #[arg(long, default_value_t = 100)]
    registry_limit: u32,

    /// Path to a PINNED open-connector checkout (must contain catalog/apps/*.json;
    /// run `npm run generate:catalog` there first). Optional supplement.
    #[arg(long)]
    open_connector: Option<PathBuf>,

    /// The pinned open-connector commit SHA (required with --open-connector).
    #[arg(long)]
    oc_sha: Option<String>,

    /// Output migration path, e.g. migrations/0010_catalog_import.sql.
    #[arg(long)]
    out: PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();

    if args.registry_url.is_none()
        && args.registry_snapshot.is_none()
        && args.open_connector.is_none()
    {
        bail!("nothing to import — pass at least one of --registry-url, --registry-snapshot, or --open-connector");
    }

    // ── MCP Registry (primary) ──────────────────────────────────────────
    let registry: Vec<RegistryEntry> = if let Some(path) = &args.registry_snapshot {
        read_registry_snapshot(path)?
    } else if let Some(base) = &args.registry_url {
        fetch_registry(base, args.registry_limit)?
    } else if args.registry_ref.is_some() {
        // A ref with no source is a mistake worth catching early.
        bail!("--registry-ref set but no --registry-url/--registry-snapshot to import from");
    } else {
        Vec::new()
    };
    if !registry.is_empty() && args.registry_ref.is_none() {
        eprintln!("warning: importing Registry rows without --registry-ref — provenance/header will be unpinned");
    }

    // ── open-connector (supplement) ─────────────────────────────────────
    let (oc_providers, oc_sha) = match &args.open_connector {
        Some(src) => {
            let sha = args
                .oc_sha
                .clone()
                .context("--oc-sha is required with --open-connector")?;
            (read_open_connector(src)?, Some(sha))
        }
        None => (Vec::new(), None),
    };

    let pins = Pins {
        registry_ref: args.registry_ref.clone(),
        open_connector_sha: oc_sha,
    };

    let result = build(&registry, oc_providers, &pins);
    for d in &result.dropped {
        eprintln!("drop {}: {}", d.service, d.reason);
    }
    if result.rows.is_empty() {
        bail!("no entries survived screening — refusing to write an empty migration");
    }

    let sql = emit_migration(&result.rows, &pins);
    std::fs::write(&args.out, &sql).with_context(|| format!("writing {}", args.out.display()))?;

    let reg = result
        .rows
        .iter()
        .filter(|r| r.source == "mcp-registry")
        .count();
    let oc = result
        .rows
        .iter()
        .filter(|r| r.source == "open-connector")
        .count();
    eprintln!(
        "wrote {} rows to {} ({} registry, {} open-connector; {} dropped)",
        result.rows.len(),
        args.out.display(),
        reg,
        oc,
        result.dropped.len(),
    );
    Ok(())
}

/// Page `GET {base}/v0/servers?limit=&cursor=` to exhaustion, following
/// `metadata.nextCursor`. Query params are encoded by reqwest.
fn fetch_registry(base: &str, limit: u32) -> Result<Vec<RegistryEntry>> {
    let base = base.trim_end_matches('/');
    let default_note = if base == DEFAULT_REGISTRY {
        ""
    } else {
        " (custom)"
    };
    eprintln!("paging MCP Registry at {base}/v0/servers{default_note}");
    let client = reqwest::blocking::Client::builder()
        .user_agent("fluidbox-catalog-import")
        .build()
        .context("building HTTP client")?;
    let mut entries = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let mut params: Vec<(&str, String)> = vec![("limit", limit.to_string())];
        if let Some(c) = &cursor {
            params.push(("cursor", c.clone()));
        }
        let url = reqwest::Url::parse_with_params(&format!("{base}/v0/servers"), &params)
            .context("building Registry URL")?;
        let page: RegistryPage = client
            .get(url)
            .send()
            .context("Registry request failed")?
            .error_for_status()
            .context("Registry returned an error status")?
            .json()
            .context("decoding Registry page")?;
        let n = page.servers.len();
        entries.extend(page.servers);
        match page.metadata.next_cursor {
            Some(c) if !c.is_empty() && n > 0 => cursor = Some(c),
            _ => break,
        }
    }
    eprintln!("fetched {} Registry server records", entries.len());
    Ok(entries)
}

/// Read a captured Registry snapshot: a single page `{servers:[…]}`, an array
/// of pages, or a bare array of server entries. Shape disambiguation lives in
/// the library (`parse_registry_snapshot`) so it is unit-tested.
fn read_registry_snapshot(path: &Path) -> Result<Vec<RegistryEntry>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading Registry snapshot {}", path.display()))?;
    parse_registry_snapshot(&text)
        .map_err(|e| anyhow::anyhow!("{e}"))
        .with_context(|| format!("parsing Registry snapshot {}", path.display()))
}

/// Read a pinned open-connector checkout's generated catalog JSON.
fn read_open_connector(src: &Path) -> Result<Vec<OcProvider>> {
    let apps = src.join("catalog/apps");
    if !apps.is_dir() {
        bail!(
            "{} not found — run `npm run generate:catalog` in the open-connector checkout first",
            apps.display()
        );
    }
    let mut providers = Vec::new();
    let mut entries: Vec<PathBuf> = std::fs::read_dir(&apps)
        .with_context(|| format!("reading {}", apps.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("json"))
        .collect();
    entries.sort();
    for path in &entries {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        match serde_json::from_str::<OcProvider>(&text) {
            Ok(p) => providers.push(p),
            Err(e) => eprintln!("skip {}: parse error: {e}", path.display()),
        }
    }
    Ok(providers)
}
