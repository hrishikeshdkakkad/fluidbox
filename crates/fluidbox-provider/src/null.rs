//! A provider that provisions NOTHING — the queue/lifecycle test double
//! (run admission design 2026-08-23 §12).
//!
//! Feature-gated behind `test-provider` so a RELEASE build cannot select it:
//! `FLUIDBOX_PROVIDER=null` on a production binary stays an unknown-provider
//! boot error, because the arm that would accept it does not exist there.
//!
//! What it is for: proving admission, dispatch, backoff and expiry over real
//! HTTP against a real database, with zero containers and zero model spend.
//! The queue is entirely a control-plane concern — nothing about admission
//! depends on what a sandbox does once it exists — so a provider that returns
//! a synthetic handle instantly exercises every path the real ones take up to
//! and including `provision`.
//!
//! What it is NOT for: anything that reads a sandbox's behaviour. It never
//! runs an agent, never produces a diff, and never dies on its own.

use async_trait::async_trait;
use fluidbox_core::traits::{
    CapacityKind, CollectContext, CollectedArtifacts, ExecutionProvider, ProviderError,
    SandboxHandle, SandboxSpec, SandboxStatus,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use uuid::Uuid;

/// The synthetic handle. Shaped exactly like `DockerProvider::provision`'s —
/// `runtime` names the backend, `external_id` is the substrate's id, `attrs`
/// carries whatever that backend needs to reattach — so nothing downstream can
/// tell it apart structurally from a real one.
fn null_handle(session_id: Uuid) -> SandboxHandle {
    SandboxHandle {
        runtime: "null".to_string(),
        external_id: format!("null-{session_id}"),
        attrs: serde_json::json!({ "session": session_id }),
    }
}

pub struct NullProvider {
    /// How many more provisions answer `CapacityDenied`
    /// (`FLUIDBOX_NULL_CAPACITY_DENIALS`). This is the lever the bounce test
    /// pulls: it makes a substrate quota refusal reproducible without a
    /// Kubernetes cluster or a ResourceQuota.
    deny_remaining: AtomicUsize,
}

impl NullProvider {
    pub fn from_env() -> Self {
        let n = std::env::var("FLUIDBOX_NULL_CAPACITY_DENIALS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        // Say it at boot: a test double whose injection knob silently read as
        // zero would make a bounce test pass for the wrong reason.
        tracing::info!("null provider: {n} injected capacity denial(s) armed");
        Self {
            deny_remaining: AtomicUsize::new(n),
        }
    }
}

#[async_trait]
impl ExecutionProvider for NullProvider {
    async fn provision(&self, spec: &SandboxSpec) -> Result<SandboxHandle, ProviderError> {
        // `fetch_update` returning Err means `checked_sub` saturated at zero,
        // i.e. no denials remain. Doing it as one atomic update rather than a
        // load-then-store keeps the count exact under the concurrent
        // provisions a cap above 1 produces.
        if self
            .deny_remaining
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok()
        {
            // `Quota` rather than `Throttle`: the injected denial models the
            // namespace ResourceQuota rejection the feature exists to survive,
            // and the e2e asserts the operator metric carries that label.
            return Err(ProviderError::CapacityDenied {
                kind: CapacityKind::Quota,
                detail: "null provider: injected quota denial".into(),
            });
        }
        Ok(null_handle(spec.session_id))
    }

    /// Never dies on its own — tests drive terminal states through the API
    /// (cancel) or the queue's own sweepers, so nothing races them.
    async fn state(&self, _handle: &SandboxHandle) -> Result<SandboxStatus, ProviderError> {
        Ok(SandboxStatus::Running)
    }

    /// Collection RAN and found nothing, which is materially different from
    /// `Missing`: the finalizer treats a missing collection as something to
    /// explain in the timeline, and a run that never had an agent has nothing
    /// to explain.
    async fn collect_artifacts(
        &self,
        _handle: Option<&SandboxHandle>,
        _ctx: &CollectContext,
    ) -> Result<CollectedArtifacts, ProviderError> {
        Ok(CollectedArtifacts::Collected(vec![]))
    }

    async fn terminate(&self, _handle: &SandboxHandle) -> Result<(), ProviderError> {
        Ok(())
    }

    /// Nothing to reconcile: no sandbox outlives the process, so the boot
    /// orphan sweep and the periodic reconciler both correctly find nothing.
    async fn list_managed(&self) -> Result<Vec<(Uuid, SandboxHandle)>, ProviderError> {
        Ok(vec![])
    }

    async fn healthcheck(&self) -> Result<(), ProviderError> {
        Ok(())
    }

    fn runtime_name(&self) -> &'static str {
        "null"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_denial_counter_is_exhaustible_and_saturates() {
        let p = NullProvider {
            deny_remaining: AtomicUsize::new(2),
        };
        // Two denials, then handles forever — the shape the bounce test needs:
        // a run that is refused, backs off, and eventually gets in.
        let take = || {
            p.deny_remaining
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                .is_ok()
        };
        assert!(take());
        assert!(take());
        assert!(!take());
        assert!(!take(), "saturates at zero rather than wrapping");
    }
}
