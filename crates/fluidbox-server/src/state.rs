use crate::config::Config;
use chrono::{DateTime, Utc};
use fluidbox_core::event::Redactor;
use fluidbox_core::traits::ExecutionProvider;
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{broadcast, Mutex, Notify};
use uuid::Uuid;

/// Wakeups for blocked permission requests. The DB approval row is the
/// source of truth; this only saves us from polling too often. On restart
/// the map is empty and the permission handler falls back to its poll tick,
/// so nothing hangs.
#[derive(Default)]
pub struct ApprovalRegistry {
    waiters: Mutex<HashMap<Uuid, Arc<Notify>>>,
}

impl ApprovalRegistry {
    pub async fn notifier(&self, approval_id: Uuid) -> Arc<Notify> {
        let mut w = self.waiters.lock().await;
        w.entry(approval_id)
            .or_insert_with(|| Arc::new(Notify::new()))
            .clone()
    }

    pub async fn wake(&self, approval_id: Uuid) {
        if let Some(n) = self.waiters.lock().await.get(&approval_id) {
            n.notify_waiters();
        }
    }

    pub async fn forget(&self, approval_id: Uuid) {
        self.waiters.lock().await.remove(&approval_id);
    }
}

/// A cached short-lived provider token and its expiry.
type CachedToken = (String, DateTime<Utc>);
/// The access/installation-token cache, keyed by
/// `(connection_id, authorization_generation)` (design :783-789).
type ConnectorTokenCache = Mutex<HashMap<(Uuid, i32), CachedToken>>;

pub struct AppStateInner {
    pub cfg: Config,
    pub pool: PgPool,
    pub tenant_id: Uuid,
    pub redactor: Redactor,
    /// The active execution backend (Docker default, Kubernetes optional) —
    /// a trait object so `FLUIDBOX_PROVIDER` selects at boot without any call
    /// site knowing which backend it drives.
    pub provider: Arc<dyn ExecutionProvider>,
    pub approvals: ApprovalRegistry,
    /// LISTEN/NOTIFY wakeups (session_id, seq) for SSE fanout.
    pub events_tx: broadcast::Sender<(Uuid, i64)>,
    /// The plain client for OPERATOR-configured seams only (GitHub REST/App, LLM
    /// facade + admin). Those hosts are operator-set (GHES, a private LiteLLM),
    /// never attacker input, so they are deliberately NOT run through the SSRF
    /// private-IP block. Attacker-influenced destinations ride the hardened
    /// clients below.
    pub http: reqwest::Client,
    /// Per-hop-SSRF client for identity fetches (OIDC discovery, JWKS, token) AND
    /// connector-OAuth (discovery, PRM, AS metadata, DCR, code exchange, refresh —
    /// Phase E). Three complementary layers cover the SSRF surface, none of which
    /// is sufficient alone: (1) the INITIAL hop's host literal is checked by
    /// `egress::admit_url` PRE-FLIGHT at each call site — reqwest dials an IP
    /// literal directly, so the resolver never sees it and the literal MUST be
    /// caught before the request (oauth.rs/login.rs do this); (2) a DNS *name* is
    /// filtered at resolve time by the custom resolver (rebinding-safe); (3) every
    /// REDIRECT hop is re-validated by the custom redirect policy. See
    /// `egress::build_identity_http` — callers into attacker-influenced endpoints
    /// admit_url the target first.
    pub identity_http: reqwest::Client,
    /// Hardened client for connector traffic to ARBITRARY user endpoints: broker
    /// MCP calls, snapshot/probe discovery, and delivery webhook publish (Phase
    /// E). Refuses ALL redirects (`Policy::none`) and filters resolved addresses
    /// via the same DNS resolver (see `egress::build_egress_http`).
    pub egress_http: reqwest::Client,
    /// The resolved egress boundary, built once in `main.rs` from config. The
    /// broker/deliveries consult it via `egress::admit_url`; the orchestrator
    /// derives the workspace `GitEgressPolicy` from it.
    pub egress_policy: crate::egress::EgressPolicy,
    /// Seals/unseals connection credentials (Phase D versioned envelope). Built
    /// by `seal::build_sealer`: a legacy key (KMS off), a KMS-envelope backend
    /// (static|aws), or None — sealing disabled — ONLY when KMS is off AND
    /// FLUIDBOX_CREDENTIAL_KEY is unset. When None, connection endpoints and
    /// connection-backed workspaces refuse to operate.
    pub sealer: Option<crate::seal::Sealer>,
    /// Short-lived provider tokens minted per connection (GitHub App
    /// installation tokens ~1h, OAuth access tokens) — a cache only; the
    /// durable credential (private key / rotating refresh token) stays
    /// sealed in the DB and entries re-mint on expiry or restart.
    /// Keyed by `(connection_id, authorization_generation)` (design :783-789):
    /// a re-consent bump makes the old generation's cached token unreachable, so
    /// a run bound to the old generation can never be served the new identity's
    /// token. Eviction (`oauth::invalidate_access`) drops EVERY generation of a
    /// connection.
    pub connector_tokens: ConnectorTokenCache,
    /// Per-connection serialization of OAuth token refreshes: rotation means
    /// concurrent brokered calls must mint ONE new refresh token, not race
    /// each other into invalid_grant (Notion keeps ≤2 valid).
    pub oauth_locks: Mutex<HashMap<Uuid, Arc<Mutex<()>>>>,
    /// Per-tenant LiteLLM virtual keys, cached UNSEALED in memory (Phase D, #32),
    /// keyed by tenant_id. The durable key stays sealed in `tenant_llm_keys`; this
    /// is a read-through of that sealed column (re-seeded on a cold cache /
    /// restart) so the facade avoids an unseal per model request. No TTL — a
    /// virtual key is durable; rotation is the only invalidation
    /// (`llm_keys::rotate_tenant_key` re-seeds it, `evict_tenant_llm_key` drops it).
    /// Only populated in `FLUIDBOX_LLM_KEY_MODE=tenant`.
    pub tenant_llm_keys: Mutex<HashMap<Uuid, String>>,
    /// Kubernetes netpol run-gate: false until a probe proves the CNI enforces
    /// NetworkPolicy. `create_run` refuses while false + require_enforced_netpol
    /// (fails closed). Always true for Docker (a different isolation model).
    pub netpol_verified: std::sync::atomic::AtomicBool,
    /// OIDC login runtime: the generation-keyed JWKS cache (singleflight
    /// refresh + negative-kid cache) and the fixed-window login rate counters.
    /// In-memory, single-replica (v1); a restart re-seeds from the DB caches.
    pub oidc: crate::login::OidcRuntime,
    /// Legacy→KMS re-seal singleton flag (Phase D, #32). `POST /v1/admin/reseal`
    /// claims it with a compare-and-swap; a second POST while a job runs gets a
    /// 409. The job is restart-safe by construction (predicate-driven paging), so
    /// this flag lives only in memory — a crash mid-job leaves no lock to clear.
    pub reseal_running: std::sync::atomic::AtomicBool,
    /// Live progress of the current/last re-seal run (per-family
    /// resealed/skipped/failed + last_error), surfaced by `GET /v1/admin/reseal`
    /// alongside the authoritative live parity counts.
    pub reseal_status: Mutex<crate::reseal::ResealStatus>,
}

pub type AppState = Arc<AppStateInner>;
