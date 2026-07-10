use crate::config::Config;
use fluidbox_core::event::Redactor;
use fluidbox_provider::DockerProvider;
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
    pub provider: Arc<DockerProvider>,
    pub approvals: ApprovalRegistry,
    /// LISTEN/NOTIFY wakeups (session_id, seq) for SSE fanout.
    pub events_tx: broadcast::Sender<(Uuid, i64)>,
    pub http: reqwest::Client,
    /// Seals/unseals connection credentials. None until
    /// FLUIDBOX_CREDENTIAL_KEY is configured — connection endpoints and
    /// connection-backed workspaces refuse to operate without it.
    pub sealer: Option<crate::seal::Sealer>,
}

pub type AppState = Arc<AppStateInner>;
