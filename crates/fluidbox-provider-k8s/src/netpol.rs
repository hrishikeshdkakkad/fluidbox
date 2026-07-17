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

use crate::config::K8sConfig;
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

/// Pure probe-Pod assembly (no cluster I/O — unit-tested like `manifest`).
/// The probe carries the SANDBOX placement + pull secrets (gate parity):
/// NetworkPolicy enforcement is per-node CNI agent, so a probe scheduled on a
/// different pool than sandboxes certifies the wrong nodes (M3); a private
/// probe image needs the same pull secrets in the sandbox namespace (M10).
/// The managed label makes the sandbox egress policy apply to the probe.
pub fn build_probe_pod(
    cfg: &K8sConfig,
    name: &str,
    probe_image: &str,
    script: &str,
) -> serde_json::Value {
    let mut pod_spec = serde_json::json!({
        "restartPolicy": "Never",
        "automountServiceAccountToken": false,
        "activeDeadlineSeconds": 60,
        "securityContext": { "runAsNonRoot": true, "runAsUser": cfg.run_as_user,
            "seccompProfile": { "type": "RuntimeDefault" } },
        "containers": [{
            "name": "probe",
            "image": probe_image,
            "command": ["/bin/sh", "-c", script],
            "securityContext": { "allowPrivilegeEscalation": false,
                "capabilities": { "drop": ["ALL"] } },
        }],
    });
    crate::manifest::apply_cluster_policy(&mut pod_spec, cfg);
    serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": { "name": name, "labels": { crate::manifest::LABEL_MANAGED: "true" } },
        "spec": pod_spec,
    })
}

/// Launch a probe Pod in the sandbox namespace (sandbox label so the egress
/// policy applies) that MUST reach the internal Service :8788 and MUST NOT
/// reach the public Service :8787, then map its terminal phase to a verdict.
/// Cleans up the probe Pod on every path.
pub async fn verify_netpol(
    cfg: &K8sConfig,
    probe_image: &str,
    internal_ip: &str,
    public_ip: &str,
) -> NetpolResult {
    let client = match Client::try_default().await {
        Ok(c) => c,
        Err(_) => return NetpolResult::ProbeError,
    };
    let pods: Api<Pod> = Api::namespaced(client, &cfg.namespace);
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
    let manifest: Pod =
        match serde_json::from_value(build_probe_pod(cfg, name, probe_image, &script)) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{K8sConfig, Toleration};

    fn cfg() -> K8sConfig {
        K8sConfig::from_env()
    }

    #[test]
    fn probe_pod_carries_sandbox_placement_and_pull_secrets() {
        // Gate parity (M3/M10): the probe must schedule exactly where sandbox
        // pods schedule, or the verdict certifies the wrong node pool.
        let mut c = cfg();
        c.run_as_user = 12345;
        c.runtime_class_name = Some("gvisor".into());
        c.priority_class_name = Some("sandbox-low".into());
        c.node_selector = vec![("pool".into(), "sandbox".into())];
        c.tolerations = vec![Toleration {
            key: Some("dedicated".into()),
            operator: Some("Equal".into()),
            value: Some("fluidbox".into()),
            effect: Some("NoSchedule".into()),
            toleration_seconds: None,
        }];
        c.image_pull_secrets = vec!["regcred".into()];

        let pod = build_probe_pod(&c, "probe-x", "busybox:1.36", "echo hi");
        let spec = &pod["spec"];
        assert_eq!(spec["runtimeClassName"], "gvisor");
        assert_eq!(spec["priorityClassName"], "sandbox-low");
        assert_eq!(spec["nodeSelector"]["pool"], "sandbox");
        assert_eq!(spec["tolerations"][0]["key"], "dedicated");
        assert_eq!(spec["tolerations"][0]["effect"], "NoSchedule");
        assert_eq!(spec["imagePullSecrets"][0]["name"], "regcred");
        // The sandbox uid baseline, not a hardcoded one.
        assert_eq!(spec["securityContext"]["runAsUser"], 12345);
        assert_eq!(spec["containers"][0]["image"], "busybox:1.36");
        assert_eq!(pod["metadata"]["name"], "probe-x");
        // The managed label makes the sandbox egress policy apply to the probe.
        assert_eq!(
            pod["metadata"]["labels"][crate::manifest::LABEL_MANAGED],
            "true"
        );
    }

    #[test]
    fn probe_pod_omits_unset_placement() {
        let pod = build_probe_pod(&cfg(), "probe-x", "busybox:1.36", "echo hi");
        let spec = &pod["spec"];
        for key in [
            "runtimeClassName",
            "priorityClassName",
            "nodeSelector",
            "tolerations",
            "imagePullSecrets",
        ] {
            assert!(spec.get(key).is_none(), "{key} should be absent");
        }
        // Baseline invariants survive.
        assert_eq!(spec["restartPolicy"], "Never");
        assert_eq!(spec["automountServiceAccountToken"], false);
        assert_eq!(spec["securityContext"]["runAsNonRoot"], true);
    }
}
