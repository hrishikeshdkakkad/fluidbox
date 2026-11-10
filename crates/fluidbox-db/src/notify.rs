//! The LISTEN/NOTIFY wakeup relays.

use fluidbox_obs::field::error_kind as EK;
use sqlx::postgres::PgListener;
use uuid::Uuid;

// ─── LISTEN/NOTIFY wakeup hub ─────────────────────────────────────────────

/// The LISTEN/NOTIFY channel a committed approval DECISION announces itself on
/// (Phase E, #33; Gap 13). Payload = the approval id, so every replica can wake
/// its own local waiters for that row. Deliberately separate from
/// `fluidbox_events` (payload `session:seq`): approvals key on the approval id,
/// and a listener that had to parse two payload shapes off one channel would be a
/// silent-misroute hazard. Like SSE, the NOTIFY is ONLY a wakeup — the wait loop's
/// ≤2 s poll re-read of Postgres stays the delivery truth (missed notifies, Neon
/// scale-to-zero).
pub const APPROVALS_CHANNEL: &str = "fluidbox_approvals";

/// Spawns the notify listener with a reconnect loop. Payloads are
/// (session_id, seq). Delivery is best-effort by design — every consumer
/// polls the seq catch-up query as the source of truth.
///
/// The LISTEN/NOTIFY relay runs on its OWN connection (outside the app pool) and
/// needs NO tenant GUC: `LISTEN fluidbox_events` and the `pg_notify` payloads it
/// receives (`session_id:seq`) are not table reads, so RLS never applies here. The
/// notify is only a wakeup — the `seq` catch-up query that actually delivers events
/// rides the RLS-scoped `events_after` on the app pool (via the SSE handlers), so
/// this connection deliberately stays role-plain (it does not even need the runtime
/// role; it only LISTENs).
pub fn spawn_listener(database_url: String) -> tokio::sync::broadcast::Sender<(Uuid, i64)> {
    spawn_channel_listener(database_url, "fluidbox_events", |payload| {
        let (sid, seq) = payload.split_once(':')?;
        Some((Uuid::parse_str(sid).ok()?, seq.parse::<i64>().ok()?))
    })
}

/// The cross-replica approval-decision wakeup (Phase E, #33; Gap 13, plan E12).
/// Every committed decision transaction `pg_notify`s [`APPROVALS_CHANNEL`] with
/// the approval id; this listener relays it so EVERY replica can wake its own
/// local `/permission` waiters, not just the one that happened to serve the
/// decision request. Same discipline as `spawn_listener` above: a dedicated
/// connection outside the app pool, role-plain, LISTEN-only, auto-reconnecting.
///
/// It is a LATENCY optimization, never the correctness mechanism — the wait loop's
/// ≤2 s Postgres re-read stays the source of truth and the missed-notify /
/// scale-to-zero backstop, exactly as `events_after` does for SSE.
pub fn spawn_approval_listener(database_url: String) -> tokio::sync::broadcast::Sender<Uuid> {
    spawn_channel_listener(database_url, APPROVALS_CHANNEL, |payload| {
        Uuid::parse_str(payload).ok()
    })
}

/// The shared LISTEN relay both channels ride. Runs on its OWN connection (outside
/// the app pool) and needs NO tenant GUC: `LISTEN` and the `pg_notify` payloads it
/// receives are not table reads, so RLS never applies here (the RLS-scoped
/// catch-up queries that actually deliver run on the app pool). Undeliverable
/// payloads are dropped, and a dropped connection reconnects with a 3 s backoff —
/// a missed notify only costs the consumer's polling interval.
fn spawn_channel_listener<T, F>(
    database_url: String,
    channel: &'static str,
    parse: F,
) -> tokio::sync::broadcast::Sender<T>
where
    T: Clone + Send + 'static,
    F: Fn(&str) -> Option<T> + Send + 'static,
{
    let (tx, _) = tokio::sync::broadcast::channel::<T>(1024);
    let tx2 = tx.clone();
    tokio::spawn(async move {
        loop {
            match PgListener::connect(&database_url).await {
                Ok(mut listener) => {
                    if listener.listen(channel).await.is_err() {
                        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                        continue;
                    }
                    tracing::info!(channel = %channel, "postgres listener connected");
                    loop {
                        match listener.recv().await {
                            Ok(n) => {
                                if let Some(v) = parse(n.payload()) {
                                    let _ = tx2.send(v);
                                }
                            }
                            Err(e) => {
                                tracing::warn!(
                                    channel = %channel,
                                    error = %e,
                                    error_kind = EK::DB,
                                    retrying = true,
                                    "postgres listener dropped; reconnecting"
                                );
                                break;
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(channel = %channel, error = %e, error_kind = EK::DB, retrying = true, "postgres listener connect failed");
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        }
    });
    tx
}
