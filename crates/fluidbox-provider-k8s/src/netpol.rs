//! Two cluster-facing helpers the server calls directly when
//! `FLUIDBOX_PROVIDER=kubernetes` (kept out of the `ExecutionProvider` trait —
//! they are deployment concerns, not per-run lifecycle):
//!
//! - `resolve_service_clusterip`: the runner's control URL under zeroEgress is
//!   the internal Service's ClusterIP (NetworkPolicy can't target a Service by
//!   name, and DNS is blocked), so the server reads it at boot.
//! - `verify_netpol`: the boot-time run-gate (design 2026-07-15). A probe pod
//!   in the sandbox namespace proves the CNI enforces the policy (+:8788 /
//!   -:8787) before any run is admitted. FAILS CLOSED.

use k8s_openapi::api::core::v1::{Pod, Service};
use kube::api::{Api, DeleteParams, PostParams};
use kube::Client;
use std::time::Duration;

/// The boot/periodic verification result. `Unschedulable` and `NotEnforced`
/// have different remediation, so they are distinguished.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetpolResult {
    Enforced,
    NotEnforced,
    Unschedulable,
    /// The probe itself errored (apiserver, RBAC) — treated as unverified.
    ProbeError,
}

/// Read a Service's ClusterIP (family-matched primary), for the runner's
/// no-DNS control URL. None if the Service or its ClusterIP is absent.
pub async fn resolve_service_clusterip(
    namespace: &str,
    name: &str,
) -> anyhow::Result<Option<String>> {
    let client = Client::try_default().await?;
    let svcs: Api<Service> = Api::namespaced(client, namespace);
    let svc = svcs.get_opt(name).await?;
    Ok(svc
        .and_then(|s| s.spec)
        .and_then(|s| s.cluster_ip)
        .filter(|ip| !ip.is_empty() && ip != "None"))
}

/// Launch a probe Pod in the sandbox namespace (sandbox label so the egress
/// policy applies) that MUST reach the internal Service :8788 and MUST NOT
/// reach the public Service :8787, then map its terminal phase to a verdict.
/// Cleans up the probe Pod on every path.
pub async fn verify_netpol(
    sandbox_namespace: &str,
    probe_image: &str,
    internal_ip: &str,
    public_ip: &str,
) -> NetpolResult {
    let client = match Client::try_default().await {
        Ok(c) => c,
        Err(_) => return NetpolResult::ProbeError,
    };
    let pods: Api<Pod> = Api::namespaced(client, sandbox_namespace);
    let name = "fluidbox-netpol-probe";
    // Idempotent: clear a stale probe from a prior boot.
    let _ = pods.delete(name, &DeleteParams::default()).await;

    let script = format!(
        "set -u; \
         if nc -z -w 4 {int} 8788; then echo pos-ok; else echo pos-fail; exit 2; fi; \
         if nc -z -w 4 {pub} 8787; then echo neg-fail; exit 3; else echo neg-ok; fi; \
         echo enforced",
        int = internal_ip,
        pub = public_ip,
    );
    let manifest: Pod = match serde_json::from_value(serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": { "name": name, "labels": { "fluidbox.dev/managed": "true" } },
        "spec": {
            "restartPolicy": "Never",
            "automountServiceAccountToken": false,
            "activeDeadlineSeconds": 60,
            "securityContext": { "runAsNonRoot": true, "runAsUser": 10001,
                "seccompProfile": { "type": "RuntimeDefault" } },
            "containers": [{
                "name": "probe",
                "image": probe_image,
                "command": ["/bin/sh", "-c", script],
                "securityContext": { "allowPrivilegeEscalation": false,
                    "capabilities": { "drop": ["ALL"] } },
            }],
        },
    })) {
        Ok(p) => p,
        Err(_) => return NetpolResult::ProbeError,
    };

    if pods
        .create(&PostParams::default(), &manifest)
        .await
        .is_err()
    {
        return NetpolResult::ProbeError;
    }

    let deadline = std::time::Instant::now() + Duration::from_secs(90);
    let verdict = loop {
        if std::time::Instant::now() > deadline {
            break NetpolResult::Unschedulable;
        }
        match pods.get_opt(name).await {
            Ok(Some(pod)) => {
                let phase = pod
                    .status
                    .as_ref()
                    .and_then(|s| s.phase.as_deref())
                    .unwrap_or("");
                match phase {
                    // Probe exited 0 → both assertions held → enforced.
                    "Succeeded" => break NetpolResult::Enforced,
                    // Non-zero: exit 3 = negative reachable (NOT enforced);
                    // exit 2 = positive unreachable (policy too tight / server
                    // down). Both mean "do not admit runs" — surface NotEnforced
                    // vs Unschedulable by the terminated exit code.
                    "Failed" => {
                        let code = pod
                            .status
                            .as_ref()
                            .and_then(|s| s.container_statuses.as_ref())
                            .and_then(|cs| cs.first())
                            .and_then(|c| c.state.as_ref())
                            .and_then(|st| st.terminated.as_ref())
                            .map(|t| t.exit_code);
                        break match code {
                            Some(3) => NetpolResult::NotEnforced,
                            _ => NetpolResult::Unschedulable,
                        };
                    }
                    _ => {}
                }
            }
            Ok(None) => break NetpolResult::ProbeError,
            Err(_) => break NetpolResult::ProbeError,
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    };

    let _ = pods.delete(name, &DeleteParams::default()).await;
    verdict
}
