//! Where the packed workspace archive LIVES (Phase F, Task 4).
//!
//! The archive is the control-plane→pod transport: the orchestrator packs one
//! `tar.gz` during `initializing`, and the sandbox's init container pulls it
//! back over HTTP from `GET /internal/sessions/{id}/workspace`. Until now that
//! file sat on a `ReadWriteOnce` PVC, which is exactly one node — so a second
//! server replica could serve a GET for an archive it does not have, and the run
//! would fail to materialize its workspace. That PVC is the first hard blocker
//! to running two servers (design 2026-07-14, lines 1041-1047).
//!
//! ## What moves, and what deliberately does not
//!
//! ONLY the archive. The workspace TREE (`<data_dir>/workspaces/<session>`)
//! stays node-local: object storage cannot host a git checkout or back a Docker
//! bind mount, and the tree is created and consumed by the same replica inside
//! one `initializing` phase. `session_workspace_root`, the clone/copy path and
//! `cleanup_workspace` are untouched.
//!
//! The HTTP proxy path also stays. The init container already GETs the archive
//! from the control plane and verifies the length and digest it was handed;
//! swapping that for a presigned URL would change the pod manifest, the RBAC and
//! — decisively — the sandbox's egress posture, since a `zeroEgress` run pod can
//! reach ONLY the control plane's internal listener and could not dial S3 at all.
//! The `s3` backend therefore streams object → response.
//!
//! ## Two backends
//!
//! * `fs` (default) — today's behaviour, byte for byte: the packer streams
//!   straight to `<data_dir>/archives/<session>.tar.gz` and `put` is a no-op. An
//!   existing single-replica install sees no change whatsoever.
//! * `s3` — any S3-compatible store (AWS S3, MinIO, Cloudflare R2, GCS's XML
//!   API). The packer still streams to node-local staging (we need the length
//!   and digest before we can sign a single-chunk PUT, and the archive must
//!   never transit control-plane RAM), then one PUT publishes it and the staging
//!   file is unlinked.
//!
//! ## Credentials (and what this does NOT support)
//!
//! Static access key + secret from the environment, sealed by whatever the
//! deployment already does for Secrets. This is the repo's seam-of-last-resort
//! pattern, chosen here deliberately: the alternative is the AWS credential
//! chain (`aws-config`, already in the tree for KMS), which brings IRSA and
//! instance roles — but ONLY for real AWS, and the whole point of the S3
//! backend is that MinIO/R2/GCS work identically. A static pair is the only
//! credential every one of those accepts.
//!
//! NOT supported, and it should fail loudly rather than surprise someone:
//! IRSA / IAM-roles-for-service-accounts, EC2/ECS instance roles, and STS
//! auto-refresh. `FLUIDBOX_ARCHIVE_S3_SESSION_TOKEN` exists so an operator CAN
//! paste temporary credentials, but nothing here renews them — when they expire
//! every archive operation starts failing with the store's own 403 and runs fail
//! during `initializing`, at zero model spend. Long-lived keys scoped to the one
//! bucket prefix are the intended configuration.

use crate::archive::StoredArchive;
use crate::sigv4;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

/// The suffix every stored archive carries. Single-sourced: the key builder, the
/// session-id parser and the fs listing all read it.
const ARCHIVE_SUFFIX: &str = ".tar.gz";

/// Cap on an error body we will read back from the store before giving up on
/// finding a `<Code>` in it. Error responses are tiny; anything larger is a
/// misconfigured endpoint answering with something that is not S3.
const MAX_ERROR_BODY_BYTES: usize = 8 * 1024;

/// Objects requested per ListObjectsV2 page. The sweep is hourly and archives are
/// short-lived, so this is about bounding one response, not throughput.
const LIST_PAGE_SIZE: u32 = 1000;

/// Hard ceiling on list pagination, so a bucket shared with something enormous
/// cannot turn the hourly sweep into an unbounded scan.
const MAX_LIST_PAGES: usize = 100;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Which backend stores packed archives. Parsed once at boot by
/// [`parse_store_config`]; every malformed or incomplete value fails boot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArchiveStoreConfig {
    /// Node-local files under `<data_dir>/archives` — the default, and what
    /// every existing install already does.
    Fs,
    /// An S3-compatible object store.
    S3(S3Config),
}

impl ArchiveStoreConfig {
    /// Short name for boot logs and the sweep's diagnostics.
    pub fn backend(&self) -> &'static str {
        match self {
            ArchiveStoreConfig::Fs => "fs",
            ArchiveStoreConfig::S3(_) => "s3",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S3Config {
    /// Scheme + authority only, no trailing slash (`https://s3.us-east-1.amazonaws.com`,
    /// `http://minio:9000`).
    pub endpoint: String,
    pub bucket: String,
    /// The SigV4 credential-scope region. Required even for stores that ignore
    /// regions (MinIO conventionally `us-east-1`) — the signature is computed
    /// over it, so guessing it would produce a 403 nobody could explain.
    pub region: String,
    /// Key prefix, normalized to `""` or `something/`.
    pub prefix: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: Option<String>,
    /// `true` ⇒ `{endpoint}/{bucket}/{key}`; `false` ⇒ `{scheme}://{bucket}.{host}/{key}`.
    pub force_path_style: bool,
}

/// Environment variable names, single-sourced here so the parser, its error
/// messages and the tests can never drift from each other.
pub const ENV_BACKEND: &str = "FLUIDBOX_ARCHIVE_STORE";
pub const ENV_BUCKET: &str = "FLUIDBOX_ARCHIVE_S3_BUCKET";
pub const ENV_REGION: &str = "FLUIDBOX_ARCHIVE_S3_REGION";
pub const ENV_ENDPOINT: &str = "FLUIDBOX_ARCHIVE_S3_ENDPOINT";
pub const ENV_PREFIX: &str = "FLUIDBOX_ARCHIVE_S3_PREFIX";
pub const ENV_ACCESS_KEY_ID: &str = "FLUIDBOX_ARCHIVE_S3_ACCESS_KEY_ID";
pub const ENV_SECRET_ACCESS_KEY: &str = "FLUIDBOX_ARCHIVE_S3_SECRET_ACCESS_KEY";
pub const ENV_SESSION_TOKEN: &str = "FLUIDBOX_ARCHIVE_S3_SESSION_TOKEN";
pub const ENV_FORCE_PATH_STYLE: &str = "FLUIDBOX_ARCHIVE_S3_FORCE_PATH_STYLE";

/// Default key prefix — mirrors the fs layout (`<data_dir>/archives/…`), so the
/// two backends name the same session the same way.
pub const DEFAULT_PREFIX: &str = "archives/";

/// Resolve the archive-store configuration from the environment. PURE (it takes
/// a lookup closure) so every boot refusal is a unit test rather than a claim.
///
/// The `s3` backend follows the `FLUIDBOX_KMS_*` shape: the mode selects which
/// other variables become required, and a mode set without its required value
/// fails boot NAMING the variable. `fs` is the default and reads nothing else,
/// so an existing deployment is unaffected.
pub fn parse_store_config(
    get: impl Fn(&str) -> Option<String>,
) -> Result<ArchiveStoreConfig, String> {
    // Trim + treat empty as absent, exactly like the other optional knobs: a
    // stray `FLUIDBOX_ARCHIVE_S3_BUCKET=` must read as "not set" (and therefore
    // hit the named refusal below), never as a bucket named "".
    let get = |k: &str| {
        get(k)
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    };

    let backend = get(ENV_BACKEND).unwrap_or_else(|| "fs".into());
    match backend.to_ascii_lowercase().as_str() {
        "fs" => Ok(ArchiveStoreConfig::Fs),
        "s3" => {
            let require = |name: &str| {
                get(name).ok_or_else(|| {
                    format!("{ENV_BACKEND}=s3 requires {name} (it is unset or empty)")
                })
            };
            let bucket = require(ENV_BUCKET)?;
            let region = require(ENV_REGION)?;
            let access_key_id = require(ENV_ACCESS_KEY_ID)?;
            let secret_access_key = require(ENV_SECRET_ACCESS_KEY)?;
            let endpoint = match get(ENV_ENDPOINT) {
                Some(raw) => normalize_endpoint(&raw)?,
                // No endpoint ⇒ real AWS S3 in the configured region.
                None => format!("https://s3.{region}.amazonaws.com"),
            };
            // Path style is the right default for EVERY S3-compatible store that
            // is not AWS itself (MinIO, R2 and the GCS XML API all address the
            // bucket in the path), and virtual-host style is the right default
            // for AWS. "An endpoint was configured" is precisely that
            // distinction, so it picks the default — and the knob overrides it.
            let force_path_style = match get(ENV_FORCE_PATH_STYLE) {
                None => get(ENV_ENDPOINT).is_some(),
                Some(v) => match v.to_ascii_lowercase().as_str() {
                    "1" | "true" | "yes" | "on" => true,
                    "0" | "false" | "no" | "off" => false,
                    other => {
                        return Err(format!(
                            "{ENV_FORCE_PATH_STYLE}='{other}' is not a valid boolean \
                             (use 1/0, true/false, yes/no, on/off)"
                        ))
                    }
                },
            };
            Ok(ArchiveStoreConfig::S3(S3Config {
                endpoint,
                bucket,
                region,
                prefix: normalize_prefix(get(ENV_PREFIX).as_deref().unwrap_or(DEFAULT_PREFIX)),
                access_key_id,
                secret_access_key,
                session_token: get(ENV_SESSION_TOKEN),
                force_path_style,
            }))
        }
        other => Err(format!(
            "{ENV_BACKEND}='{other}' is invalid (known: fs, s3)"
        )),
    }
}

/// `scheme://host[:port]`, trailing slash removed. A path, query or fragment is
/// REFUSED rather than silently dropped: `.../my-bucket` in the endpoint is the
/// classic misconfiguration, and honouring it would sign one URL and send
/// another.
fn normalize_endpoint(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim().trim_end_matches('/');
    let rest = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .ok_or_else(|| format!("{ENV_ENDPOINT}='{raw}' must start with http:// or https://"))?;
    if rest.is_empty() {
        return Err(format!("{ENV_ENDPOINT}='{raw}' has no host"));
    }
    if rest.contains('/') || rest.contains('?') || rest.contains('#') {
        return Err(format!(
            "{ENV_ENDPOINT}='{raw}' must be scheme://host[:port] only — no path, query or \
             fragment (the bucket goes in {ENV_BUCKET}, not the endpoint)"
        ));
    }
    if rest.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(format!("{ENV_ENDPOINT}='{raw}' contains whitespace"));
    }
    Ok(trimmed.to_string())
}

/// `""` or `something/` — no leading slash, exactly one trailing slash.
fn normalize_prefix(raw: &str) -> String {
    let t = raw.trim().trim_start_matches('/');
    if t.is_empty() {
        String::new()
    } else {
        format!("{}/", t.trim_end_matches('/'))
    }
}

/// The fs backend is single-replica by construction: the archive lands on one
/// node's disk and the GET can be routed to any replica behind the Service. That
/// is not a subtle degradation — it is a run that fails to materialize its
/// workspace — so a deployment that DECLARES more than one replica is refused at
/// boot rather than discovering it under load.
///
/// The control plane cannot observe its own replica count, so the declaration is
/// the chart's (`FLUIDBOX_REPLICAS`, templated from `.Values.server.replicas`).
/// Undeclared means 1, which is what every existing install is.
pub fn validate_replicas(cfg: &ArchiveStoreConfig, replicas: u32) -> Result<(), String> {
    if replicas > 1 && matches!(cfg, ArchiveStoreConfig::Fs) {
        return Err(format!(
            "FLUIDBOX_REPLICAS={replicas} but {ENV_BACKEND}=fs — the workspace archive would live \
             on ONE replica's disk while the sandbox's init container GETs it through the Service, \
             so a run whose GET lands on any other replica fails to materialize its workspace. \
             Set {ENV_BACKEND}=s3 (with {ENV_BUCKET}/{ENV_REGION}/{ENV_ACCESS_KEY_ID}/\
             {ENV_SECRET_ACCESS_KEY}) for a multi-replica deployment, or run one replica."
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The store interface
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The archive is not there. Distinct from every other failure because the
    /// callers act on it: `delete` treats it as success, and the HTTP handler
    /// answers 404 (a retryable 5xx for anything else).
    #[error("archive not found")]
    NotFound,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Backend(String),
}

/// A byte stream of one stored archive, streamed to the init container's
/// response. Never buffered whole — an archive is capped at `max_archive_bytes`
/// (2 GiB by default) and must not transit control-plane RAM.
pub type ArchiveStream =
    std::pin::Pin<Box<dyn futures::Stream<Item = Result<bytes::Bytes, std::io::Error>> + Send>>;

/// An open archive: its exact length (the response's `Content-Length`) and its
/// body. The length comes from the STORE, not from a local `File::metadata`.
pub struct ArchiveRead {
    pub len: u64,
    pub stream: ArchiveStream,
}

impl std::fmt::Debug for ArchiveRead {
    /// Hand-written because the body is a boxed stream — `Debug` exists so a
    /// `Result<ArchiveRead, StoreError>` can be `unwrap_err()`ed in tests.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArchiveRead")
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

/// One stored archive, as the backend names it. Opaque to callers: the only
/// things it can do are name a session and be handed back to
/// [`ArchiveStore::delete_key`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArchiveKey {
    /// A node-local file: the whole story for the `fs` backend, and — for `s3` —
    /// a staging file some crash left behind before it could be uploaded.
    Local(PathBuf),
    /// An object key in the remote store.
    Object(String),
}

impl ArchiveKey {
    /// The session this archive belongs to, from its `{uuid}.tar.gz` (or
    /// `.partial`) basename. `None` = not a name this server writes, which the
    /// sweep treats as reclaimable.
    pub fn session_id(&self) -> Option<Uuid> {
        let name = match self {
            ArchiveKey::Local(p) => p.file_name()?.to_str()?,
            ArchiveKey::Object(k) => k.rsplit('/').next()?,
        };
        let stem = name
            .strip_suffix(&format!("{ARCHIVE_SUFFIX}.partial"))
            .or_else(|| name.strip_suffix(ARCHIVE_SUFFIX))?;
        Uuid::parse_str(stem).ok()
    }
}

impl std::fmt::Display for ArchiveKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ArchiveKey::Local(p) => write!(f, "{}", p.display()),
            ArchiveKey::Object(k) => write!(f, "s3:{k}"),
        }
    }
}

/// The five storage-shaped operations the control plane performs on a workspace
/// archive, plus the one path helper that decides where the packer writes.
///
/// The call sites are, in order: pack/publish (`orchestrator::pack_and_store_archive`),
/// serve (`internal::workspace_archive`), delete-at-finalize
/// (`orchestrator::delete_archive`), the TTL sweep's listing and its per-key
/// delete (`workers::archive_ttl_sweep`).
#[async_trait::async_trait]
pub trait ArchiveStore: Send + Sync + std::fmt::Debug {
    /// `"fs"` or `"s3"` — for boot and sweep logs.
    fn backend(&self) -> &'static str;

    /// The LOCAL path the packer streams this session's archive to. For `fs`
    /// this is the final resting place (so `put` is a no-op and the behaviour is
    /// today's, byte for byte); for `s3` it is node-local staging that `put`
    /// uploads and then unlinks.
    fn staging_path(&self, session_id: Uuid) -> PathBuf;

    /// Publish an archive the packer just wrote to [`Self::staging_path`].
    /// `packed.sha256`/`packed.len` describe the exact bytes — the digest is
    /// reused as the single-chunk payload hash rather than recomputed over a
    /// second full read of the file.
    async fn put(&self, session_id: Uuid, packed: &StoredArchive) -> Result<(), StoreError>;

    /// Open the stored archive for streaming, with the length the response must
    /// declare. `NotFound` when there is no such archive.
    async fn get(&self, session_id: Uuid) -> Result<ArchiveRead, StoreError>;

    /// Delete a session's archive. Absence is SUCCESS (idempotent); any other
    /// failure surfaces so the terminal reconciler retries instead of leaking.
    async fn delete(&self, session_id: Uuid) -> Result<(), StoreError>;

    /// Stored archives (including orphaned `.partial`s) untouched for longer
    /// than `ttl` — sweep CANDIDATES only. Deletion is decided by the caller
    /// against SESSION STATE: age alone must never kill an archive a long-budget
    /// run could still re-fetch on an init re-execution.
    async fn stale_candidates(&self, ttl: Duration) -> Result<Vec<ArchiveKey>, StoreError>;

    /// Delete one candidate returned by [`Self::stale_candidates`].
    async fn delete_key(&self, key: &ArchiveKey) -> Result<(), StoreError>;
}

/// Build the configured store. Infallible: [`parse_store_config`] already
/// refused every incoherent configuration at boot, so nothing is left to fail
/// here. `http` is the control plane's plain outbound client — an S3 endpoint is
/// an operator-configured seam exactly like GitHub or the LLM upstream (it is
/// routinely a private-network MinIO), never attacker input, so it deliberately
/// does not ride the SSRF-filtered clients.
pub fn build_store(
    cfg: &ArchiveStoreConfig,
    data_dir: &Path,
    http: reqwest::Client,
) -> Arc<dyn ArchiveStore> {
    // Both backends use `<data_dir>/archives`: the fs one as the archive's home,
    // the s3 one as staging. Sharing the directory means an operator who
    // switches fs→s3 still has the old files swept by the same TTL pass.
    let dir = data_dir.join("archives");
    match cfg {
        ArchiveStoreConfig::Fs => Arc::new(FsArchiveStore { dir }),
        ArchiveStoreConfig::S3(s3) => Arc::new(S3ArchiveStore {
            staging: dir,
            cfg: s3.clone(),
            http,
        }),
    }
}

// ---------------------------------------------------------------------------
// fs backend — today's behaviour, unchanged
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct FsArchiveStore {
    dir: PathBuf,
}

/// Stream a file in 64 KiB chunks. This is the exact loop the archive handler
/// used to run inline; it moved here so the `fs` backend stays byte-identical
/// while the handler became backend-agnostic. An error is yielded ONCE and then
/// the stream ends (the old loop `break`s after yielding the error).
fn file_stream(file: tokio::fs::File) -> ArchiveStream {
    Box::pin(futures::stream::unfold(
        (Some(file), vec![0u8; 64 * 1024]),
        |(file, mut buf)| async move {
            let mut file = file?;
            match tokio::io::AsyncReadExt::read(&mut file, &mut buf).await {
                Ok(0) => None,
                Ok(n) => {
                    let chunk = bytes::Bytes::copy_from_slice(&buf[..n]);
                    Some((Ok(chunk), (Some(file), buf)))
                }
                Err(e) => Some((Err(e), (None, buf))),
            }
        },
    ))
}

#[async_trait::async_trait]
impl ArchiveStore for FsArchiveStore {
    fn backend(&self) -> &'static str {
        "fs"
    }

    fn staging_path(&self, session_id: Uuid) -> PathBuf {
        self.dir.join(format!("{session_id}{ARCHIVE_SUFFIX}"))
    }

    /// No-op: the packer already streamed the archive to its final path, which
    /// is what this backend has always done.
    async fn put(&self, _session_id: Uuid, _packed: &StoredArchive) -> Result<(), StoreError> {
        Ok(())
    }

    async fn get(&self, session_id: Uuid) -> Result<ArchiveRead, StoreError> {
        let path = self.staging_path(session_id);
        let file = tokio::fs::File::open(&path)
            .await
            .map_err(|_| StoreError::NotFound)?;
        let len = file
            .metadata()
            .await
            .map_err(|_| StoreError::NotFound)?
            .len();
        Ok(ArchiveRead {
            len,
            stream: file_stream(file),
        })
    }

    async fn delete(&self, session_id: Uuid) -> Result<(), StoreError> {
        match std::fs::remove_file(self.staging_path(session_id)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    async fn stale_candidates(&self, ttl: Duration) -> Result<Vec<ArchiveKey>, StoreError> {
        Ok(stale_local_files(&self.dir, ttl))
    }

    async fn delete_key(&self, key: &ArchiveKey) -> Result<(), StoreError> {
        delete_archive_key(key, None).await
    }
}

/// List node-local archive files older than `ttl`. Failures are LOGGED, never
/// silent — a persistent PVC error would otherwise retain a leak with no
/// operational evidence. Shared by the `fs` backend (its whole listing) and the
/// `s3` backend (its staging-leak half).
fn stale_local_files(dir: &Path, ttl: Duration) -> Vec<ArchiveKey> {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        // No archives ever stored (e.g. the Docker provider): quiet no-op.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
        Err(e) => {
            tracing::warn!("archive TTL sweep cannot read {}: {e}", dir.display());
            return Vec::new();
        }
    };
    let now = std::time::SystemTime::now();
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!("archive TTL sweep cannot stat {}: {e}", path.display());
                continue;
            }
        };
        if !meta.is_file() {
            continue;
        }
        let mtime = match meta.modified() {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!("archive TTL sweep: no mtime for {}: {e}", path.display());
                continue;
            }
        };
        // A future-dated mtime (clock skew) reads as fresh — conservative.
        let stale = now
            .duration_since(mtime)
            .map(|age| age >= ttl)
            .unwrap_or(false);
        if stale {
            out.push(ArchiveKey::Local(path));
        }
    }
    out
}

/// Delete one candidate. A `Local` key is a file on this node whichever backend
/// produced it; an `Object` key needs the store that owns it, so a backend that
/// cannot serve one says so instead of silently reporting success.
async fn delete_archive_key(
    key: &ArchiveKey,
    s3: Option<&S3ArchiveStore>,
) -> Result<(), StoreError> {
    match (key, s3) {
        (ArchiveKey::Local(path), _) => match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        },
        (ArchiveKey::Object(k), Some(store)) => store.delete_object(k).await,
        (ArchiveKey::Object(k), None) => Err(StoreError::Backend(format!(
            "object key '{k}' cannot be deleted by the fs backend"
        ))),
    }
}

// ---------------------------------------------------------------------------
// s3 backend
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct S3ArchiveStore {
    /// Node-local staging for the pack step (never the archive's home).
    staging: PathBuf,
    cfg: S3Config,
    http: reqwest::Client,
}

impl S3ArchiveStore {
    fn key_for(&self, session_id: Uuid) -> String {
        format!("{}{session_id}{ARCHIVE_SUFFIX}", self.cfg.prefix)
    }

    /// The wire URL and the canonical URI for one key — computed together
    /// BECAUSE they must agree: signing one path and requesting another is the
    /// single most common way a hand-rolled SigV4 produces an unexplainable 403.
    /// Returns `(url, canonical_uri, host)`.
    fn address(&self, key: &str) -> (String, String, String) {
        // Path components are encoded WITHOUT encoding `/`: S3's canonical URI
        // keeps the path separators (and does not double-encode).
        let encoded_key = sigv4::uri_encode(key, false);
        let (scheme, host) = self
            .cfg
            .endpoint
            .split_once("://")
            .map(|(s, h)| (s.to_string(), h.to_string()))
            .unwrap_or_else(|| ("https".into(), self.cfg.endpoint.clone()));
        if self.cfg.force_path_style {
            let bucket = sigv4::uri_encode(&self.cfg.bucket, false);
            (
                format!("{scheme}://{host}/{bucket}/{encoded_key}"),
                format!("/{bucket}/{encoded_key}"),
                host,
            )
        } else {
            let vhost = format!("{}.{host}", self.cfg.bucket);
            (
                format!("{scheme}://{vhost}/{encoded_key}"),
                format!("/{encoded_key}"),
                vhost,
            )
        }
    }

    /// The bucket root — path style puts the bucket in the path, virtual-host
    /// style in the authority, and ListObjectsV2 needs whichever it is.
    fn bucket_address(&self) -> (String, String, String) {
        let (scheme, host) = self
            .cfg
            .endpoint
            .split_once("://")
            .map(|(s, h)| (s.to_string(), h.to_string()))
            .unwrap_or_else(|| ("https".into(), self.cfg.endpoint.clone()));
        if self.cfg.force_path_style {
            let bucket = sigv4::uri_encode(&self.cfg.bucket, false);
            (
                format!("{scheme}://{host}/{bucket}/"),
                format!("/{bucket}/"),
                host,
            )
        } else {
            let vhost = format!("{}.{host}", self.cfg.bucket);
            (format!("{scheme}://{vhost}/"), "/".to_string(), vhost)
        }
    }

    /// Assemble the signed header set for one request. `host`, `x-amz-date`,
    /// `x-amz-content-sha256` and (when present) `x-amz-security-token` are
    /// signed AND sent — a header on the wire that was not signed is a 403.
    fn signed_headers(
        &self,
        method: &str,
        canonical_uri: &str,
        canonical_query: &str,
        host: &str,
        payload_sha256: &str,
        extra: &[(&str, String)],
    ) -> Vec<(String, String)> {
        let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        let mut headers: BTreeMap<String, String> = BTreeMap::new();
        headers.insert("host".into(), host.to_string());
        headers.insert("x-amz-date".into(), amz_date.clone());
        headers.insert("x-amz-content-sha256".into(), payload_sha256.to_string());
        if let Some(token) = &self.cfg.session_token {
            headers.insert("x-amz-security-token".into(), token.clone());
        }
        for (k, v) in extra {
            headers.insert(k.to_ascii_lowercase(), v.clone());
        }
        let creds = sigv4::Credentials {
            access_key_id: self.cfg.access_key_id.clone(),
            secret_access_key: self.cfg.secret_access_key.clone(),
            session_token: self.cfg.session_token.clone(),
        };
        let signed = sigv4::sign(
            &creds,
            &self.cfg.region,
            "s3",
            &amz_date,
            method,
            canonical_uri,
            canonical_query,
            &headers,
            payload_sha256,
        );
        // `host` is set by the HTTP client from the URL; sending it again would
        // be redundant but harmless — sending it DIFFERENTLY would not be, so it
        // is dropped here and the URL remains the single source of truth.
        let mut out: Vec<(String, String)> =
            headers.into_iter().filter(|(k, _)| k != "host").collect();
        out.push(("authorization".into(), signed.authorization));
        out
    }

    async fn delete_object(&self, key: &str) -> Result<(), StoreError> {
        let (url, canonical_uri, host) = self.address(key);
        let headers = self.signed_headers(
            "DELETE",
            &canonical_uri,
            "",
            &host,
            sigv4::EMPTY_PAYLOAD_SHA256,
            &[],
        );
        let mut req = self.http.delete(&url);
        for (k, v) in headers {
            req = req.header(k, v);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| StoreError::Backend(format!("DELETE {key}: {e}")))?;
        // S3 answers 204 for a delete whether or not the key existed — deletion
        // is idempotent at the protocol level, which is exactly what the
        // terminal reconciler needs. A 404 from a non-AWS implementation is
        // treated the same way.
        if resp.status().is_success() || resp.status().as_u16() == 404 {
            return Ok(());
        }
        Err(self.error_from(resp, "DELETE", key).await)
    }

    /// Render a non-success response as a `StoreError`, pulling S3's `<Code>`
    /// out of the XML body when there is one. Bounded — an endpoint answering
    /// with something enormous must not be read into memory.
    async fn error_from(&self, resp: reqwest::Response, verb: &str, key: &str) -> StoreError {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        let body: String = body.chars().take(MAX_ERROR_BODY_BYTES).collect();
        let code = first_tag(&body, "Code").unwrap_or_else(|| "(no code)".into());
        StoreError::Backend(format!(
            "{verb} {key}: {} from the object store ({code})",
            status.as_u16()
        ))
    }
}

#[async_trait::async_trait]
impl ArchiveStore for S3ArchiveStore {
    fn backend(&self) -> &'static str {
        "s3"
    }

    fn staging_path(&self, session_id: Uuid) -> PathBuf {
        self.staging.join(format!("{session_id}{ARCHIVE_SUFFIX}"))
    }

    async fn put(&self, session_id: Uuid, packed: &StoredArchive) -> Result<(), StoreError> {
        let key = self.key_for(session_id);
        let result = self.put_inner(&key, packed).await;
        // Staging is scratch either way: on success it has been uploaded, and on
        // failure the whole pack is redone from the workspace on the next drive.
        // Leaving it would leak a node-local copy of every failed run until the
        // TTL sweep noticed.
        let _ = std::fs::remove_file(&packed.path);
        result
    }

    async fn get(&self, session_id: Uuid) -> Result<ArchiveRead, StoreError> {
        use futures::TryStreamExt;
        let key = self.key_for(session_id);
        let (url, canonical_uri, host) = self.address(&key);
        let headers = self.signed_headers(
            "GET",
            &canonical_uri,
            "",
            &host,
            sigv4::EMPTY_PAYLOAD_SHA256,
            &[],
        );
        let mut req = self.http.get(&url);
        for (k, v) in headers {
            req = req.header(k, v);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| StoreError::Backend(format!("GET {key}: {e}")))?;
        if resp.status().as_u16() == 404 {
            return Err(StoreError::NotFound);
        }
        if !resp.status().is_success() {
            return Err(self.error_from(resp, "GET", &key).await);
        }
        // The length comes from the STORE. The old handler read it from
        // `File::metadata`; there is no file here, and a wrong or missing
        // Content-Length would make the init container's own length check fail
        // AFTER a full download rather than here.
        let len = resp.content_length().ok_or_else(|| {
            StoreError::Backend(format!(
                "GET {key}: the object store sent no Content-Length"
            ))
        })?;
        let stream = resp.bytes_stream().map_err(std::io::Error::other);
        Ok(ArchiveRead {
            len,
            stream: Box::pin(stream),
        })
    }

    async fn delete(&self, session_id: Uuid) -> Result<(), StoreError> {
        // Belt and braces: a crash between pack and put can leave staging behind
        // for a session that is now terminal, and finalize is the natural place
        // to reclaim it (the TTL sweep is only the backstop).
        let _ = std::fs::remove_file(self.staging_path(session_id));
        self.delete_object(&self.key_for(session_id)).await
    }

    async fn stale_candidates(&self, ttl: Duration) -> Result<Vec<ArchiveKey>, StoreError> {
        // BOTH halves: the objects themselves, and any node-local staging file a
        // crash left behind before it could be uploaded. Without the second half
        // moving the archive to S3 would have swapped one leak for another.
        let mut out = stale_local_files(&self.staging, ttl);
        out.extend(self.stale_objects(ttl).await?);
        Ok(out)
    }

    async fn delete_key(&self, key: &ArchiveKey) -> Result<(), StoreError> {
        delete_archive_key(key, Some(self)).await
    }
}

impl S3ArchiveStore {
    async fn put_inner(&self, key: &str, packed: &StoredArchive) -> Result<(), StoreError> {
        let (url, canonical_uri, host) = self.address(key);
        // The packer already digested the exact bytes it wrote (`sha256:<hex>`),
        // so single-chunk signing costs nothing extra — no second full read.
        let payload = packed
            .sha256
            .strip_prefix("sha256:")
            .ok_or_else(|| {
                StoreError::Backend(format!(
                    "packed archive digest '{}' is not in sha256:<hex> form",
                    packed.sha256
                ))
            })?
            .to_string();
        let headers = self.signed_headers(
            "PUT",
            &canonical_uri,
            "",
            &host,
            &payload,
            &[("content-type", "application/gzip".to_string())],
        );
        let file = tokio::fs::File::open(&packed.path).await?;
        let mut req = self.http.put(&url);
        for (k, v) in headers {
            req = req.header(k, v);
        }
        // CONTENT_LENGTH is LOAD-BEARING. `reqwest::Body::from(File)` wraps the
        // file in a `ReaderStream`, whose size hint is unknown, and hyper then
        // sends `Transfer-Encoding: chunked` — which S3 rejects for a
        // single-chunk PUT. hyper's `set_length` honours an explicitly-set
        // Content-Length over the body's hint, so setting it here is what makes
        // the request sized. A test drives a real socket and asserts both that
        // content-length is present and that transfer-encoding is not.
        let resp = req
            .header(reqwest::header::CONTENT_LENGTH, packed.len)
            .body(reqwest::Body::from(file))
            .send()
            .await
            .map_err(|e| StoreError::Backend(format!("PUT {key}: {e}")))?;
        if !resp.status().is_success() {
            return Err(self.error_from(resp, "PUT", key).await);
        }
        Ok(())
    }

    /// ListObjectsV2 over our prefix, keeping objects last modified before
    /// `now - ttl`. Paginated, and bounded by [`MAX_LIST_PAGES`].
    async fn stale_objects(&self, ttl: Duration) -> Result<Vec<ArchiveKey>, StoreError> {
        let cutoff = chrono::Utc::now()
            - chrono::Duration::from_std(ttl).unwrap_or_else(|_| chrono::Duration::zero());
        let (base_url, canonical_uri, host) = self.bucket_address();
        let mut token: Option<String> = None;
        let mut out = Vec::new();
        for _ in 0..MAX_LIST_PAGES {
            let mut params: Vec<(String, String)> = vec![
                ("list-type".into(), "2".into()),
                ("max-keys".into(), LIST_PAGE_SIZE.to_string()),
            ];
            if !self.cfg.prefix.is_empty() {
                params.push(("prefix".into(), self.cfg.prefix.clone()));
            }
            if let Some(t) = &token {
                params.push(("continuation-token".into(), t.clone()));
            }
            let query = sigv4::canonical_query(&params);
            let headers = self.signed_headers(
                "GET",
                &canonical_uri,
                &query,
                &host,
                sigv4::EMPTY_PAYLOAD_SHA256,
                &[],
            );
            // The SIGNED query string is the one sent, verbatim — re-encoding it
            // through a query builder would risk a different byte sequence and a
            // 403 that only appears once a continuation token contains `/`.
            let url = format!("{base_url}?{query}");
            let mut req = self.http.get(&url);
            for (k, v) in headers {
                req = req.header(k, v);
            }
            let resp = req
                .send()
                .await
                .map_err(|e| StoreError::Backend(format!("LIST: {e}")))?;
            if !resp.status().is_success() {
                return Err(self.error_from(resp, "LIST", &self.cfg.prefix).await);
            }
            let body = resp
                .text()
                .await
                .map_err(|e| StoreError::Backend(format!("LIST: reading body: {e}")))?;
            for (key, last_modified) in list_contents(&body) {
                let Ok(ts) = chrono::DateTime::parse_from_rfc3339(&last_modified) else {
                    // Unparseable timestamp reads as FRESH — the same
                    // conservative direction the fs sweep takes on clock skew.
                    tracing::warn!("archive TTL sweep: unparseable LastModified on {key}");
                    continue;
                };
                if ts.with_timezone(&chrono::Utc) <= cutoff {
                    out.push(ArchiveKey::Object(key));
                }
            }
            match first_tag(&body, "IsTruncated").as_deref() {
                Some("true") => match first_tag(&body, "NextContinuationToken") {
                    Some(t) => token = Some(t),
                    None => break,
                },
                _ => break,
            }
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// A very small XML reader for the two ListObjectsV2 shapes we consume
// ---------------------------------------------------------------------------

/// The text of the first `<tag>…</tag>` in `xml`, entity-decoded. Deliberately
/// not a general XML parser: ListObjectsV2 is a fixed, flat, namespace-default
/// document, and the alternative is another dependency for two field reads.
fn first_tag(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    Some(xml_decode(&xml[start..end]))
}

/// `(key, last_modified)` for every `<Contents>` element.
fn list_contents(xml: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for chunk in xml.split("<Contents>").skip(1) {
        let body = chunk.split("</Contents>").next().unwrap_or(chunk);
        if let (Some(k), Some(t)) = (first_tag(body, "Key"), first_tag(body, "LastModified")) {
            out.push((k, t));
        }
    }
    out
}

/// The five predefined XML entities. Our own keys (`{uuid}.tar.gz`) contain
/// none of them, but a foreign object sharing the bucket can, and a key we
/// mis-decode is a key we would fail to delete.
fn xml_decode(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        // `&amp;` LAST: decoding it first would let `&amp;lt;` become `<`.
        .replace("&amp;", "&")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    // -----------------------------------------------------------------------
    // configuration
    // -----------------------------------------------------------------------

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |k: &str| map.get(k).cloned()
    }

    #[test]
    fn default_is_fs_and_reads_nothing_else() {
        assert_eq!(
            parse_store_config(env(&[])).unwrap(),
            ArchiveStoreConfig::Fs
        );
        assert_eq!(
            parse_store_config(env(&[(ENV_BACKEND, "fs")])).unwrap(),
            ArchiveStoreConfig::Fs
        );
        // Leftover s3 settings do NOT make an fs deployment fail or drift.
        assert_eq!(
            parse_store_config(env(&[(ENV_BACKEND, "fs"), (ENV_BUCKET, "b")])).unwrap(),
            ArchiveStoreConfig::Fs
        );
        // Whitespace-only reads as unset, not as a backend named " ".
        assert_eq!(
            parse_store_config(env(&[(ENV_BACKEND, "  ")])).unwrap(),
            ArchiveStoreConfig::Fs
        );
    }

    #[test]
    fn unknown_backend_fails_boot_naming_the_choices() {
        let e = parse_store_config(env(&[(ENV_BACKEND, "gcs")])).unwrap_err();
        assert!(e.contains(ENV_BACKEND), "{e}");
        assert!(e.contains("known: fs, s3"), "{e}");
    }

    fn s3_env() -> Vec<(&'static str, &'static str)> {
        vec![
            (ENV_BACKEND, "s3"),
            (ENV_BUCKET, "fbx-archives"),
            (ENV_REGION, "us-east-1"),
            (ENV_ACCESS_KEY_ID, "AKIA"),
            (ENV_SECRET_ACCESS_KEY, "SECRET"),
        ]
    }

    /// Every required-value refusal, one variable at a time: drop it, and the
    /// error must NAME it. This is the boot gate the `FLUIDBOX_KMS_*` knobs set
    /// the precedent for.
    #[test]
    fn s3_without_each_required_value_fails_boot_naming_it() {
        for missing in [
            ENV_BUCKET,
            ENV_REGION,
            ENV_ACCESS_KEY_ID,
            ENV_SECRET_ACCESS_KEY,
        ] {
            let pairs: Vec<(&str, &str)> = s3_env()
                .into_iter()
                .filter(|(k, _)| *k != missing)
                .collect();
            let e = parse_store_config(env(&pairs))
                .unwrap_err_or_panic(&format!("{missing} missing must refuse boot"));
            assert!(e.contains(missing), "error must name {missing}: {e}");
        }
        // An EMPTY value is the same as an absent one, not a value of "".
        for empty in [
            ENV_BUCKET,
            ENV_REGION,
            ENV_ACCESS_KEY_ID,
            ENV_SECRET_ACCESS_KEY,
        ] {
            let mut pairs = s3_env();
            for p in pairs.iter_mut() {
                if p.0 == empty {
                    p.1 = "   ";
                }
            }
            let e = parse_store_config(env(&pairs)).unwrap_err();
            assert!(e.contains(empty), "error must name {empty}: {e}");
        }
        // FALSE-GREEN guard: with all four present it must SUCCEED, so the
        // assertions above are about the missing value and not about `s3` never
        // parsing at all.
        assert!(matches!(
            parse_store_config(env(&s3_env())).unwrap(),
            ArchiveStoreConfig::S3(_)
        ));
    }

    #[test]
    fn s3_defaults_endpoint_prefix_and_addressing_style() {
        let ArchiveStoreConfig::S3(c) = parse_store_config(env(&s3_env())).unwrap() else {
            panic!("expected s3");
        };
        // No endpoint ⇒ real AWS in the configured region, virtual-host style.
        assert_eq!(c.endpoint, "https://s3.us-east-1.amazonaws.com");
        assert!(!c.force_path_style);
        assert_eq!(c.prefix, DEFAULT_PREFIX);
        assert_eq!(c.session_token, None);

        // A configured endpoint ⇒ path style by default (MinIO/R2/GCS-XML).
        let mut pairs = s3_env();
        pairs.push((ENV_ENDPOINT, "http://minio:9000/"));
        let ArchiveStoreConfig::S3(c) = parse_store_config(env(&pairs)).unwrap() else {
            panic!("expected s3");
        };
        assert_eq!(c.endpoint, "http://minio:9000");
        assert!(
            c.force_path_style,
            "a custom endpoint defaults to path style"
        );

        // …and the knob overrides the default in both directions.
        let mut forced_off = pairs.clone();
        forced_off.push((ENV_FORCE_PATH_STYLE, "false"));
        let ArchiveStoreConfig::S3(c) = parse_store_config(env(&forced_off)).unwrap() else {
            panic!("expected s3");
        };
        assert!(!c.force_path_style);
        let mut forced_on = s3_env();
        forced_on.push((ENV_FORCE_PATH_STYLE, "yes"));
        let ArchiveStoreConfig::S3(c) = parse_store_config(env(&forced_on)).unwrap() else {
            panic!("expected s3");
        };
        assert!(c.force_path_style);
        // A typo fails boot rather than silently picking an addressing style.
        let mut typo = s3_env();
        typo.push((ENV_FORCE_PATH_STYLE, "ture"));
        let e = parse_store_config(env(&typo)).unwrap_err();
        assert!(e.contains(ENV_FORCE_PATH_STYLE), "{e}");
    }

    #[test]
    fn endpoint_must_be_scheme_and_host_only() {
        for bad in [
            "minio:9000",                   // no scheme
            "https://",                     // no host
            "https://minio:9000/my-bucket", // bucket in the endpoint
            "https://minio:9000?x=1",
            "https://mi nio:9000",
        ] {
            let mut pairs = s3_env();
            pairs.push((ENV_ENDPOINT, Box::leak(bad.to_string().into_boxed_str())));
            let e = parse_store_config(env(&pairs))
                .unwrap_err_or_panic(&format!("endpoint '{bad}' must be refused"));
            assert!(e.contains(ENV_ENDPOINT), "{e}");
        }
    }

    #[test]
    fn prefix_is_normalized() {
        assert_eq!(normalize_prefix("archives"), "archives/");
        assert_eq!(normalize_prefix("/archives/"), "archives/");
        assert_eq!(normalize_prefix("a/b"), "a/b/");
        assert_eq!(normalize_prefix(""), "");
        assert_eq!(normalize_prefix("/"), "");
    }

    /// The multi-replica refusal, in both directions.
    #[test]
    fn fs_refuses_a_declared_multi_replica_deployment() {
        let s3 = parse_store_config(env(&s3_env())).unwrap();
        assert!(validate_replicas(&ArchiveStoreConfig::Fs, 1).is_ok());
        assert!(validate_replicas(&s3, 1).is_ok());
        assert!(validate_replicas(&s3, 5).is_ok());
        let e = validate_replicas(&ArchiveStoreConfig::Fs, 2).unwrap_err();
        assert!(e.contains("FLUIDBOX_REPLICAS=2"), "{e}");
        assert!(e.contains(ENV_BACKEND), "{e}");
        assert!(e.contains("s3"), "the fix must be named: {e}");
    }

    // -----------------------------------------------------------------------
    // key/path mapping
    // -----------------------------------------------------------------------

    #[test]
    fn keys_and_paths_map_back_to_their_session() {
        let sid = Uuid::now_v7();
        assert_eq!(
            ArchiveKey::Local(PathBuf::from(format!("/data/archives/{sid}.tar.gz"))).session_id(),
            Some(sid)
        );
        assert_eq!(
            ArchiveKey::Local(PathBuf::from(format!(
                "/data/archives/{sid}.tar.gz.partial"
            )))
            .session_id(),
            Some(sid)
        );
        assert_eq!(
            ArchiveKey::Object(format!("archives/{sid}.tar.gz")).session_id(),
            Some(sid)
        );
        assert_eq!(
            ArchiveKey::Object(format!("deep/nest/{sid}.tar.gz")).session_id(),
            Some(sid)
        );
        // Names this server does not write.
        assert_eq!(
            ArchiveKey::Local(PathBuf::from("/data/archives/junk.tar.gz")).session_id(),
            None
        );
        assert_eq!(
            ArchiveKey::Local(PathBuf::from("/data/archives/notatar")).session_id(),
            None
        );
        assert_eq!(ArchiveKey::Object("archives/".into()).session_id(), None);
    }

    fn s3_store(endpoint: &str, path_style: bool) -> S3ArchiveStore {
        S3ArchiveStore {
            staging: std::env::temp_dir().join(format!("fbx-stage-{}", Uuid::now_v7())),
            cfg: S3Config {
                endpoint: endpoint.into(),
                bucket: "fbx-archives".into(),
                region: "us-east-1".into(),
                prefix: "archives/".into(),
                access_key_id: "AKIA".into(),
                secret_access_key: "SECRET".into(),
                session_token: None,
                force_path_style: path_style,
            },
            http: reqwest::Client::new(),
        }
    }

    #[test]
    fn addressing_style_decides_url_and_canonical_uri_together() {
        let sid = Uuid::now_v7();
        let path = s3_store("https://minio.example:9000", true);
        let key = path.key_for(sid);
        assert_eq!(key, format!("archives/{sid}.tar.gz"));
        let (url, canonical, host) = path.address(&key);
        assert_eq!(
            url,
            format!("https://minio.example:9000/fbx-archives/archives/{sid}.tar.gz")
        );
        assert_eq!(canonical, format!("/fbx-archives/archives/{sid}.tar.gz"));
        assert_eq!(host, "minio.example:9000");
        // The canonical URI must be the URL's path — signing one and sending
        // another is the classic hand-rolled-SigV4 403.
        assert!(url.ends_with(&canonical));

        let vhost = s3_store("https://s3.us-east-1.amazonaws.com", false);
        let (url, canonical, host) = vhost.address(&key);
        assert_eq!(
            url,
            format!("https://fbx-archives.s3.us-east-1.amazonaws.com/archives/{sid}.tar.gz")
        );
        assert_eq!(canonical, format!("/archives/{sid}.tar.gz"));
        assert_eq!(host, "fbx-archives.s3.us-east-1.amazonaws.com");
        assert!(url.ends_with(&canonical));

        // And the bucket root, which ListObjectsV2 addresses.
        let (url, canonical, _) = path.bucket_address();
        assert_eq!(url, "https://minio.example:9000/fbx-archives/");
        assert_eq!(canonical, "/fbx-archives/");
        let (url, canonical, _) = vhost.bucket_address();
        assert_eq!(url, "https://fbx-archives.s3.us-east-1.amazonaws.com/");
        assert_eq!(canonical, "/");
    }

    #[test]
    fn signed_headers_cover_every_header_actually_sent() {
        let mut store = s3_store("https://minio.example:9000", true);
        store.cfg.session_token = Some("TOKEN".into());
        let headers = store.signed_headers(
            "GET",
            "/fbx-archives/archives/x.tar.gz",
            "",
            "minio.example:9000",
            sigv4::EMPTY_PAYLOAD_SHA256,
            &[],
        );
        let names: Vec<&str> = headers.iter().map(|(k, _)| k.as_str()).collect();
        assert!(names.contains(&"authorization"));
        assert!(names.contains(&"x-amz-date"));
        assert!(names.contains(&"x-amz-content-sha256"));
        assert!(names.contains(&"x-amz-security-token"));
        // `host` is the client's job (from the URL) and must not be duplicated.
        assert!(!names.contains(&"host"), "{names:?}");
        let auth = headers
            .iter()
            .find(|(k, _)| k == "authorization")
            .map(|(_, v)| v.clone())
            .unwrap();
        // Every header we send is in SignedHeaders, host included.
        assert!(
            auth.contains(
                "SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token"
            ),
            "{auth}"
        );
        assert!(auth.contains("/us-east-1/s3/aws4_request"), "{auth}");
    }

    // -----------------------------------------------------------------------
    // XML reading
    // -----------------------------------------------------------------------

    #[test]
    fn list_xml_is_read_correctly() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>fbx</Name><Prefix>archives/</Prefix><KeyCount>2</KeyCount>
  <IsTruncated>true</IsTruncated>
  <NextContinuationToken>1ueGc/uD+w==</NextContinuationToken>
  <Contents><Key>archives/a&amp;b.tar.gz</Key><LastModified>2013-09-17T18:07:53.000Z</LastModified><Size>7</Size></Contents>
  <Contents><Key>archives/c.tar.gz</Key><LastModified>2024-01-02T03:04:05.000Z</LastModified><Size>9</Size></Contents>
</ListBucketResult>"#;
        assert_eq!(
            list_contents(xml),
            vec![
                (
                    "archives/a&b.tar.gz".to_string(),
                    "2013-09-17T18:07:53.000Z".to_string()
                ),
                (
                    "archives/c.tar.gz".to_string(),
                    "2024-01-02T03:04:05.000Z".to_string()
                ),
            ]
        );
        assert_eq!(first_tag(xml, "IsTruncated").as_deref(), Some("true"));
        assert_eq!(
            first_tag(xml, "NextContinuationToken").as_deref(),
            Some("1ueGc/uD+w==")
        );
        assert_eq!(first_tag(xml, "Nope"), None);
        // An empty page yields nothing and does not paginate.
        let empty = "<ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>";
        assert!(list_contents(empty).is_empty());
        assert_eq!(first_tag(empty, "IsTruncated").as_deref(), Some("false"));
    }

    #[test]
    fn xml_entities_decode_amp_last() {
        assert_eq!(xml_decode("a&amp;b"), "a&b");
        assert_eq!(xml_decode("&lt;x&gt;"), "<x>");
        // `&amp;lt;` is a literal "&lt;", not a "<".
        assert_eq!(xml_decode("&amp;lt;"), "&lt;");
        assert_eq!(xml_decode("plain"), "plain");
    }

    // -----------------------------------------------------------------------
    // fs backend behaviour (the byte-for-byte baseline)
    // -----------------------------------------------------------------------

    fn tmpdir() -> PathBuf {
        let p = std::env::temp_dir().join(format!("fbx-store-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    async fn drain(mut read: ArchiveRead) -> Vec<u8> {
        use futures::StreamExt;
        let mut out = Vec::new();
        while let Some(chunk) = read.stream.next().await {
            out.extend_from_slice(&chunk.unwrap());
        }
        out
    }

    #[tokio::test]
    async fn fs_backend_is_the_old_behaviour() {
        let data = tmpdir();
        let store = build_store(&ArchiveStoreConfig::Fs, &data, reqwest::Client::new());
        assert_eq!(store.backend(), "fs");
        let sid = Uuid::now_v7();

        // The staging path IS the historical archive path.
        let staged = store.staging_path(sid);
        assert_eq!(staged, data.join("archives").join(format!("{sid}.tar.gz")));

        // Nothing stored yet ⇒ NotFound (what the handler renders as a 404).
        assert!(matches!(
            store.get(sid).await.unwrap_err(),
            StoreError::NotFound
        ));
        // …and deleting nothing is success.
        store.delete(sid).await.unwrap();

        // Pack (simulated) → put is a no-op → get streams the same bytes back.
        std::fs::create_dir_all(staged.parent().unwrap()).unwrap();
        // Larger than one 64 KiB read, so the chunking loop actually loops.
        let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        std::fs::write(&staged, &payload).unwrap();
        let packed = StoredArchive {
            path: staged.clone(),
            sha256: "sha256:unused-by-fs".into(),
            len: payload.len() as u64,
        };
        store.put(sid, &packed).await.unwrap();
        assert!(staged.is_file(), "fs put must leave the file where it was");

        let read = store.get(sid).await.unwrap();
        assert_eq!(read.len, payload.len() as u64);
        assert_eq!(drain(read).await, payload);

        // Delete is idempotent.
        store.delete(sid).await.unwrap();
        assert!(!staged.exists());
        store.delete(sid).await.unwrap();
        std::fs::remove_dir_all(&data).ok();
    }

    #[tokio::test]
    async fn fs_stale_listing_matches_the_old_sweep() {
        let data = tmpdir();
        let store = build_store(&ArchiveStoreConfig::Fs, &data, reqwest::Client::new());
        let archives = data.join("archives");
        std::fs::create_dir_all(&archives).unwrap();
        let sid = Uuid::now_v7();
        std::fs::write(archives.join(format!("{sid}.tar.gz")), b"x").unwrap();
        std::fs::write(archives.join("b.tar.gz"), b"y").unwrap();
        std::fs::create_dir_all(archives.join("subdir")).unwrap();

        // A generous TTL keeps fresh archives.
        assert!(store
            .stale_candidates(Duration::from_secs(3600))
            .await
            .unwrap()
            .is_empty());

        // A zero TTL makes everything a candidate — files only, never the dir.
        let mut got = store.stale_candidates(Duration::ZERO).await.unwrap();
        got.sort_by_key(|k| k.to_string());
        assert_eq!(got.len(), 2, "{got:?}");
        assert!(got.iter().all(|k| matches!(k, ArchiveKey::Local(_))));
        assert!(got.iter().any(|k| k.session_id() == Some(sid)));
        assert!(got.iter().any(|k| k.session_id().is_none()));

        // Deleting a candidate removes exactly that file, twice over.
        for k in &got {
            store.delete_key(k).await.unwrap();
            store.delete_key(k).await.unwrap();
        }
        assert!(!archives.join("b.tar.gz").exists());
        assert!(archives.join("subdir").is_dir());

        // A missing archives dir (the Docker provider) is a quiet no-op.
        let absent = build_store(
            &ArchiveStoreConfig::Fs,
            &data.join("nope"),
            reqwest::Client::new(),
        );
        assert!(absent
            .stale_candidates(Duration::ZERO)
            .await
            .unwrap()
            .is_empty());
        std::fs::remove_dir_all(&data).ok();
    }

    #[tokio::test]
    async fn fs_backend_refuses_an_object_key() {
        // A `Local`-only backend must never silently succeed on an object key.
        let data = tmpdir();
        let store = build_store(&ArchiveStoreConfig::Fs, &data, reqwest::Client::new());
        let err = store
            .delete_key(&ArchiveKey::Object("archives/x.tar.gz".into()))
            .await
            .unwrap_err();
        assert!(matches!(err, StoreError::Backend(_)), "{err:?}");
        std::fs::remove_dir_all(&data).ok();
    }

    // -----------------------------------------------------------------------
    // s3 backend, against an in-process fake S3 on a real socket
    // -----------------------------------------------------------------------

    /// What the fake saw. `chunked` is the one that matters most: S3 rejects a
    /// chunked single-chunk PUT, and nothing but a real socket can prove we do
    /// not send one.
    #[derive(Debug, Clone)]
    struct Recorded {
        method: String,
        target: String,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
        chunked: bool,
    }

    impl Recorded {
        fn header(&self, name: &str) -> Option<&str> {
            self.headers
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.as_str())
        }
    }

    #[derive(Default)]
    struct FakeState {
        /// key → (bytes, LastModified)
        objects: std::collections::BTreeMap<String, (Vec<u8>, String)>,
        requests: Vec<Recorded>,
    }

    struct FakeS3 {
        addr: std::net::SocketAddr,
        state: Arc<std::sync::Mutex<FakeState>>,
    }

    impl FakeS3 {
        async fn start() -> FakeS3 {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let state = Arc::new(std::sync::Mutex::new(FakeState::default()));
            let st = state.clone();
            tokio::spawn(async move {
                loop {
                    let Ok((sock, _)) = listener.accept().await else {
                        return;
                    };
                    let st = st.clone();
                    tokio::spawn(async move { serve_one(sock, st).await });
                }
            });
            FakeS3 { addr, state }
        }

        fn endpoint(&self) -> String {
            format!("http://{}", self.addr)
        }

        fn requests(&self) -> Vec<Recorded> {
            self.state.lock().unwrap().requests.clone()
        }
    }

    /// One request per connection, answered with `connection: close`. Small on
    /// purpose: the point is to observe the exact bytes our client sends.
    async fn serve_one(mut sock: tokio::net::TcpStream, state: Arc<std::sync::Mutex<FakeState>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut buf = Vec::new();
        let mut tmp = [0u8; 8192];
        // Head.
        let head_end = loop {
            let n = match sock.read(&mut tmp).await {
                Ok(0) | Err(_) => return,
                Ok(n) => n,
            };
            buf.extend_from_slice(&tmp[..n]);
            if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break p + 4;
            }
        };
        let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
        let mut lines = head.lines();
        let request_line = lines.next().unwrap_or_default().to_string();
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or_default().to_string();
        let target = parts.next().unwrap_or_default().to_string();
        let mut headers = Vec::new();
        for line in lines {
            if let Some((k, v)) = line.split_once(':') {
                headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
            }
        }
        let chunked = headers
            .iter()
            .any(|(k, v)| k == "transfer-encoding" && v.contains("chunked"));
        let want: usize = headers
            .iter()
            .find(|(k, _)| k == "content-length")
            .and_then(|(_, v)| v.parse().ok())
            .unwrap_or(0);
        let mut body = buf[head_end..].to_vec();
        while body.len() < want {
            let n = match sock.read(&mut tmp).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            body.extend_from_slice(&tmp[..n]);
        }

        let (path, query) = match target.split_once('?') {
            Some((p, q)) => (p.to_string(), q.to_string()),
            None => (target.clone(), String::new()),
        };
        // `/{bucket}/{key}` — the fake only ever runs path style.
        let key = path
            .trim_start_matches('/')
            .split_once('/')
            .map(|(_, k)| k.to_string())
            .unwrap_or_default();

        let (status, body_out): (u16, Vec<u8>) = {
            let mut st = state.lock().unwrap();
            st.requests.push(Recorded {
                method: method.clone(),
                target: target.clone(),
                headers: headers.clone(),
                body: body.clone(),
                chunked,
            });
            match method.as_str() {
                "PUT" => {
                    st.objects
                        .insert(key, (body.clone(), "2013-09-17T18:07:53.000Z".into()));
                    (200, Vec::new())
                }
                "DELETE" => {
                    st.objects.remove(&key);
                    (204, Vec::new())
                }
                "GET" if query.contains("list-type=2") => {
                    let mut xml = String::from(
                        "<?xml version=\"1.0\"?><ListBucketResult><IsTruncated>false</IsTruncated>",
                    );
                    for (k, (_, lm)) in st.objects.iter() {
                        xml.push_str(&format!(
                            "<Contents><Key>{k}</Key><LastModified>{lm}</LastModified></Contents>"
                        ));
                    }
                    xml.push_str("</ListBucketResult>");
                    (200, xml.into_bytes())
                }
                "GET" => match st.objects.get(&key) {
                    Some((bytes, _)) => (200, bytes.clone()),
                    None => (404, b"<Error><Code>NoSuchKey</Code></Error>".to_vec()),
                },
                _ => (405, Vec::new()),
            }
        };
        let head_out = format!(
            "HTTP/1.1 {status} X\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            body_out.len()
        );
        let _ = sock.write_all(head_out.as_bytes()).await;
        let _ = sock.write_all(&body_out).await;
        let _ = sock.flush().await;
        let _ = sock.shutdown().await;
    }

    fn s3_config_for(fake: &FakeS3) -> ArchiveStoreConfig {
        ArchiveStoreConfig::S3(S3Config {
            endpoint: fake.endpoint(),
            bucket: "fbx-archives".into(),
            region: "us-east-1".into(),
            prefix: "archives/".into(),
            access_key_id: "AKIA".into(),
            secret_access_key: "SECRET".into(),
            session_token: None,
            force_path_style: true,
        })
    }

    /// The whole lifecycle over a real socket: PUT the packed file, GET it back
    /// byte-for-byte with the length taken from the STORE, LIST it, DELETE it.
    #[tokio::test]
    async fn s3_round_trip_over_a_real_socket() {
        let fake = FakeS3::start().await;
        let data = tmpdir();
        let cfg = s3_config_for(&fake);
        let store = build_store(&cfg, &data, reqwest::Client::new());
        assert_eq!(store.backend(), "s3");
        let sid = Uuid::now_v7();

        // Pack (simulated) into staging.
        let staged = store.staging_path(sid);
        assert_eq!(staged, data.join("archives").join(format!("{sid}.tar.gz")));
        std::fs::create_dir_all(staged.parent().unwrap()).unwrap();
        let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        std::fs::write(&staged, &payload).unwrap();
        let digest = {
            use sha2::{Digest, Sha256};
            format!("sha256:{}", hex::encode(Sha256::digest(&payload)))
        };
        let packed = StoredArchive {
            path: staged.clone(),
            sha256: digest.clone(),
            len: payload.len() as u64,
        };

        store.put(sid, &packed).await.unwrap();
        // Staging is reclaimed: the archive's home is the bucket now.
        assert!(!staged.exists(), "s3 put must unlink the staging file");

        let put = fake.requests().pop().unwrap();
        assert_eq!(put.method, "PUT");
        assert_eq!(put.target, format!("/fbx-archives/archives/{sid}.tar.gz"));
        assert_eq!(put.body, payload, "the exact packed bytes are uploaded");
        // Sized, NOT chunked — S3 rejects a chunked single-chunk PUT.
        assert!(!put.chunked, "PUT must not use chunked transfer-encoding");
        assert_eq!(
            put.header("content-length"),
            Some(payload.len().to_string().as_str())
        );
        // Single-chunk signing reuses the packer's digest verbatim.
        assert_eq!(
            put.header("x-amz-content-sha256"),
            Some(digest.strip_prefix("sha256:").unwrap())
        );
        let auth = put.header("authorization").unwrap();
        assert!(
            auth.starts_with("AWS4-HMAC-SHA256 Credential=AKIA/"),
            "{auth}"
        );
        assert!(auth.contains("/us-east-1/s3/aws4_request"), "{auth}");
        // Everything signed is a header that was actually sent.
        let signed = auth
            .split("SignedHeaders=")
            .nth(1)
            .and_then(|s| s.split(',').next())
            .unwrap();
        for name in signed.split(';') {
            assert!(
                name == "host" || put.header(name).is_some(),
                "signed header '{name}' was not sent: {:?}",
                put.headers
            );
        }

        // GET streams the object back, with the length from the store.
        let read = store.get(sid).await.unwrap();
        assert_eq!(read.len, payload.len() as u64);
        assert_eq!(drain(read).await, payload);

        // LIST sees it; a zero TTL makes it a candidate.
        let stale = store.stale_candidates(Duration::ZERO).await.unwrap();
        assert_eq!(
            stale,
            vec![ArchiveKey::Object(format!("archives/{sid}.tar.gz"))]
        );
        assert_eq!(stale[0].session_id(), Some(sid));
        let list = fake
            .requests()
            .into_iter()
            .rev()
            .find(|r| r.target.contains("list-type=2"))
            .unwrap();
        // The signed query is the one sent, verbatim and sorted.
        assert_eq!(
            list.target,
            "/fbx-archives/?list-type=2&max-keys=1000&prefix=archives%2F"
        );

        // DELETE removes it; a second delete is still success.
        store.delete(sid).await.unwrap();
        assert!(matches!(
            store.get(sid).await.unwrap_err(),
            StoreError::NotFound
        ));
        store.delete(sid).await.unwrap();
        assert!(store
            .stale_candidates(Duration::ZERO)
            .await
            .unwrap()
            .is_empty());
        std::fs::remove_dir_all(&data).ok();
    }

    /// A store-side failure must NOT read as "not found": the handler answers
    /// 404 for absent (init gives up) and 5xx for broken (init retries).
    #[tokio::test]
    async fn s3_distinguishes_absent_from_broken() {
        let fake = FakeS3::start().await;
        let data = tmpdir();
        let store = build_store(&s3_config_for(&fake), &data, reqwest::Client::new());
        assert!(matches!(
            store.get(Uuid::now_v7()).await.unwrap_err(),
            StoreError::NotFound
        ));
        // A dead endpoint is a Backend error, never NotFound.
        let dead = ArchiveStoreConfig::S3(S3Config {
            endpoint: "http://127.0.0.1:1".into(),
            bucket: "b".into(),
            region: "us-east-1".into(),
            prefix: "archives/".into(),
            access_key_id: "AKIA".into(),
            secret_access_key: "SECRET".into(),
            session_token: None,
            force_path_style: true,
        });
        let broken = build_store(&dead, &data, reqwest::Client::new());
        assert!(matches!(
            broken.get(Uuid::now_v7()).await.unwrap_err(),
            StoreError::Backend(_)
        ));
        std::fs::remove_dir_all(&data).ok();
    }

    /// The same lifecycle against a REAL S3-compatible server, which the fake
    /// above cannot cover on its own: the fake records the signature but does not
    /// VERIFY it, so only a real implementation proves the hand-rolled SigV4 is
    /// accepted rather than merely well-formed.
    ///
    /// SELF-SKIPS without `FLUIDBOX_TEST_S3_ENDPOINT` (the `fluidbox-db` Neon-test
    /// precedent), so a laptop with no container runtime is unaffected. CI drives
    /// it with a MinIO service container; see the handover for the job.
    #[tokio::test]
    async fn s3_round_trip_against_a_real_object_store() {
        let Ok(endpoint) = std::env::var("FLUIDBOX_TEST_S3_ENDPOINT") else {
            eprintln!("skipping: FLUIDBOX_TEST_S3_ENDPOINT is unset");
            return;
        };
        let cfg = parse_store_config(|k| match k {
            ENV_BACKEND => Some("s3".into()),
            ENV_ENDPOINT => Some(endpoint.clone()),
            // Everything else comes from the environment, through the REAL
            // parser — so this also proves the shipped knobs configure a store a
            // real server accepts, not just one this crate can construct.
            other => std::env::var(other).ok(),
        })
        .expect("the FLUIDBOX_ARCHIVE_S3_* environment must be complete");
        let data = tmpdir();
        let store = build_store(&cfg, &data, reqwest::Client::new());
        let sid = Uuid::now_v7();

        let staged = store.staging_path(sid);
        std::fs::create_dir_all(staged.parent().unwrap()).unwrap();
        let payload: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
        std::fs::write(&staged, &payload).unwrap();
        let packed = StoredArchive {
            path: staged.clone(),
            sha256: format!(
                "sha256:{}",
                hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&payload))
            ),
            len: payload.len() as u64,
        };

        store.put(sid, &packed).await.expect("PUT must be accepted");
        let read = store.get(sid).await.expect("GET must be accepted");
        assert_eq!(read.len, payload.len() as u64);
        assert_eq!(drain(read).await, payload);

        // LIST must see it (a zero TTL makes everything a candidate).
        let stale = store.stale_candidates(Duration::ZERO).await.unwrap();
        assert!(
            stale.iter().any(|k| k.session_id() == Some(sid)),
            "LIST did not return the object just written: {stale:?}"
        );

        store.delete(sid).await.expect("DELETE must be accepted");
        assert!(matches!(
            store.get(sid).await.unwrap_err(),
            StoreError::NotFound
        ));
        // Deleting an absent key stays success — the terminal reconciler retries.
        store.delete(sid).await.unwrap();
        std::fs::remove_dir_all(&data).ok();
    }

    /// The leak this refactor would otherwise have introduced: a crash between
    /// pack and PUT leaves a node-local staging file that no object listing
    /// would ever show. The s3 sweep must return BOTH halves.
    #[tokio::test]
    async fn s3_sweep_covers_leaked_local_staging() {
        let fake = FakeS3::start().await;
        let data = tmpdir();
        let store = build_store(&s3_config_for(&fake), &data, reqwest::Client::new());
        let sid = Uuid::now_v7();
        let staged = store.staging_path(sid);
        std::fs::create_dir_all(staged.parent().unwrap()).unwrap();
        std::fs::write(&staged, b"never uploaded").unwrap();
        // …and a `.partial` from a pack that died mid-write.
        let partial = staged.with_extension("gz.partial");
        std::fs::write(&partial, b"half").unwrap();

        let stale = store.stale_candidates(Duration::ZERO).await.unwrap();
        assert_eq!(stale.len(), 2, "{stale:?}");
        assert!(stale
            .iter()
            .all(|k| matches!(k, ArchiveKey::Local(_)) && k.session_id() == Some(sid)));
        for k in &stale {
            store.delete_key(k).await.unwrap();
        }
        assert!(!staged.exists() && !partial.exists());
        std::fs::remove_dir_all(&data).ok();
    }

    /// A failed upload must not leave the staging file behind either — the pack
    /// is redone from the workspace on the next drive.
    #[tokio::test]
    async fn s3_failed_put_reclaims_staging() {
        let data = tmpdir();
        let dead = ArchiveStoreConfig::S3(S3Config {
            endpoint: "http://127.0.0.1:1".into(),
            bucket: "b".into(),
            region: "us-east-1".into(),
            prefix: "archives/".into(),
            access_key_id: "AKIA".into(),
            secret_access_key: "SECRET".into(),
            session_token: None,
            force_path_style: true,
        });
        let store = build_store(&dead, &data, reqwest::Client::new());
        let sid = Uuid::now_v7();
        let staged = store.staging_path(sid);
        std::fs::create_dir_all(staged.parent().unwrap()).unwrap();
        std::fs::write(&staged, b"x").unwrap();
        let packed = StoredArchive {
            path: staged.clone(),
            sha256: format!(
                "sha256:{}",
                hex::encode(<sha2::Sha256 as sha2::Digest>::digest(b"x"))
            ),
            len: 1,
        };
        assert!(store.put(sid, &packed).await.is_err());
        assert!(!staged.exists(), "a failed put must reclaim staging");
        std::fs::remove_dir_all(&data).ok();
    }

    /// Tiny helper so the "missing variable" loop can name which case failed.
    trait UnwrapErrOrPanic<T> {
        fn unwrap_err_or_panic(self, msg: &str) -> String;
    }
    impl<T: std::fmt::Debug> UnwrapErrOrPanic<T> for Result<T, String> {
        fn unwrap_err_or_panic(self, msg: &str) -> String {
            match self {
                Err(e) => e,
                Ok(v) => panic!("{msg} (got Ok({v:?}))"),
            }
        }
    }
}
