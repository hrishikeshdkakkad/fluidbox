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
    pub http: reqwest::Client,
    /// Seals/unseals connection credentials. None until
    /// FLUIDBOX_CREDENTIAL_KEY is configured — connection endpoints and
    /// connection-backed workspaces refuse to operate without it.
    pub sealer: Option<crate::seal::Sealer>,
    /// Short-lived provider tokens minted per connection (GitHub App
    /// installation tokens ~1h, OAuth access tokens) — a cache only; the
    /// durable credential (private key / rotating refresh token) stays
    /// sealed in the DB and entries re-mint on expiry or restart.
    pub connector_tokens: Mutex<HashMap<Uuid, (String, DateTime<Utc>)>>,
    /// Per-connection serialization of OAuth token refreshes: rotation means
    /// concurrent brokered calls must mint ONE new refresh token, not race
    /// each other into invalid_grant (Notion keeps ≤2 valid).
    pub oauth_locks: Mutex<HashMap<Uuid, Arc<Mutex<()>>>>,
    /// Kubernetes netpol run-gate: false until a probe proves the CNI enforces
    /// NetworkPolicy. `create_run` refuses while false + require_enforced_netpol
    /// (fails closed). Always true for Docker (a different isolation model).
    pub netpol_verified: std::sync::atomic::AtomicBool,
    /// OIDC login runtime: the generation-keyed JWKS cache (singleflight
    /// refresh + negative-kid cache) and the fixed-window login rate counters.
    /// In-memory, single-replica (v1); a restart re-seeds from the DB caches.
    pub oidc: crate::login::OidcRuntime,
}

pub type AppState = Arc<AppStateInner>;
