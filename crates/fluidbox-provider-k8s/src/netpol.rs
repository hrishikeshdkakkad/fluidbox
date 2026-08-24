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
use fluidbox_obs::field::error_kind as EK;
use k8s_openapi::api::core::v1::{Pod, Service};
use kube::api::{Api, DeleteParams, LogParams, PostParams};
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

/// Scheduling + image-pull slack added on top of the observation window for
/// the probe Pod's own `activeDeadlineSeconds` (the script self-terminates at
/// `wait_secs`; this bound only fires if the pod never got to run it).
pub const PROBE_SCHEDULING_SLACK_SECS: u64 = 60;
/// Extra slack the CALLER (the gate worker) waits beyond the pod's own
/// deadline before concluding `Unschedulable` — covers apiserver lag between
/// the kubelet killing the pod and the phase landing.
pub const PROBE_CALLER_SLACK_SECS: u64 = 90;

/// The bounded, observable enforcement-wait script (busybox sh). This is the
/// SINGLE source of the admission protocol, shared verbatim by the boot-time
/// certification probe and the per-sandbox `netpol-gate` init container.
///
/// Why a convergence LOOP and not one sample: CNIs may program NetworkPolicy
/// for a new pod asynchronously (AWS VPC CNI `standard` mode fails OPEN for
/// ~20s — measured 2026-07-28, docs/reviews/2026-07-27 §8c). A t=0 sample
/// measures the unprogrammed network; a fixed sleep would encode a timing
/// guess. This loop OBSERVES: each iteration tests the positive target (must
/// be reachable — the allow rule) and the negative target (must be blocked —
/// the deny), succeeding only when BOTH hold in the SAME observation.
/// Enforcement is monotonic once programmed, so the first such observation is
/// proof. On deadline it fails CLOSED with the original exit-code contract:
///   0 = enforced; 3 = negative still reachable (NotEnforced);
///   2 = positive still unreachable (Unschedulable / policy too tight).
/// Every iteration prints an `obs …` line, so the pod log is a timestamped
/// record of exactly what was measured — the observable half of the protocol.
pub fn enforcement_script(positive: (&str, u16), negative: (&str, u16), wait_secs: u64) -> String {
    format!(
        "set -u; \
         end=$(( $(date +%s) + {wait} )); i=0; \
         while :; do \
           i=$((i+1)); pos=fail; neg=blocked; \
           nc -z -w 2 {pos_host} {pos_port} && pos=ok; \
           nc -z -w 2 {neg_host} {neg_port} && neg=open; \
           echo \"obs $i t=$(date +%s) pos=$pos neg=$neg\"; \
           if [ \"$pos\" = ok ] && [ \"$neg\" = blocked ]; then echo enforced; exit 0; fi; \
           if [ $(date +%s) -ge $end ]; then \
             if [ \"$neg\" = open ]; then echo \"deadline: negative still reachable — NOT enforced\"; exit 3; fi; \
             echo \"deadline: positive unreachable — policy too tight or server down\"; exit 2; \
           fi; \
           sleep 1; \
         done",
        wait = wait_secs,
        pos_host = positive.0,
        pos_port = positive.1,
        neg_host = negative.0,
        neg_port = negative.1,
    )
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
    wait_secs: u64,
) -> serde_json::Value {
    let mut pod_spec = serde_json::json!({
        "restartPolicy": "Never",
        "automountServiceAccountToken": false,
        // The script self-terminates at `wait_secs`; the pod deadline only
        // adds scheduling/pull slack on top — never a second, shorter clock
        // that could kill a still-observing probe.
        "activeDeadlineSeconds": wait_secs + PROBE_SCHEDULING_SLACK_SECS,
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
/// policy applies) that runs the bounded observation loop: it must OBSERVE
/// the internal Service :8788 reachable AND the public Service :8787 blocked
/// within `wait_secs` (CNIs that program policy asynchronously converge
/// inside the window instead of failing a t=0 sample). Terminal phase maps to
/// the verdict; on failure the probe's own observation log is surfaced so the
/// operator sees exactly what was measured. Cleans up the probe Pod on every
/// path.
pub async fn verify_netpol(
    cfg: &K8sConfig,
    probe_image: &str,
    internal_ip: &str,
    public_ip: &str,
    wait_secs: u64,
) -> NetpolResult {
    let client = match Client::try_default().await {
        Ok(c) => c,
        Err(_) => return NetpolResult::ProbeError,
    };
    let pods: Api<Pod> = Api::namespaced(client, &cfg.namespace);
    let name = "fluidbox-netpol-probe";
    // Idempotent: clear a stale probe from a prior boot.
    let _ = pods.delete(name, &DeleteParams::default()).await;

    let script = enforcement_script((internal_ip, 8788), (public_ip, 8787), wait_secs);
    let manifest: Pod =
        match serde_json::from_value(build_probe_pod(cfg, name, probe_image, &script, wait_secs)) {
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

    // The pod runs the observation window itself; this outer clock only adds
    // scheduling slack on top of the pod's own deadline. Derived, never a
    // separate magic number — a caller clock shorter than the observation
    // window would re-introduce the t=0 race it exists to fix.
    let deadline = std::time::Instant::now()
        + Duration::from_secs(wait_secs + PROBE_SCHEDULING_SLACK_SECS + PROBE_CALLER_SLACK_SECS);
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
                    // Probe exited 0 → both assertions held in one
                    // observation → enforced.
                    "Succeeded" => break NetpolResult::Enforced,
                    // Non-zero after the FULL observation window: exit 3 =
                    // negative still reachable (NOT enforced); exit 2 =
                    // positive still unreachable (policy too tight / server
                    // down). Both mean "do not admit runs" — surface
                    // NotEnforced vs Unschedulable by the terminated exit code.
                    "Failed" => {
                        let code = pod
                            .status
                            .as_ref()
                            .and_then(|s| s.container_statuses.as_ref())
                            .and_then(|cs| cs.first())
                            .and_then(|c| c.state.as_ref())
                            .and_then(|st| st.terminated.as_ref())
                            .map(|t| t.exit_code);
                        // The observation log is the evidence — surface its
                        // tail rather than a bare exit code.
                        let tail = probe_log_tail(&pods, name).await;
                        tracing::warn!(
                            exit_code = ?code,
                            observations = %tail,
                            error_kind = EK::PROVIDER,
                            "netpol enforcement probe failed"
                        );
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

/// Last observation lines from the probe pod, best-effort (the verdict never
/// depends on this — it is operator evidence only).
async fn probe_log_tail(pods: &Api<Pod>, name: &str) -> String {
    let lp = LogParams {
        tail_lines: Some(12),
        ..Default::default()
    };
    match pods.logs(name, &lp).await {
        Ok(l) if !l.trim().is_empty() => l,
        _ => "(no probe log available)".into(),
    }
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

        let pod = build_probe_pod(&c, "probe-x", "busybox:1.36", "echo hi", 60);
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
        let pod = build_probe_pod(&cfg(), "probe-x", "busybox:1.36", "echo hi", 60);
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

    /// The admission race regression (measured on EKS 2026-07-28,
    /// docs/reviews/2026-07-27 §8c): the probe must OBSERVE convergence over a
    /// bounded window, never sample once at t=0 and never sleep-then-assume.
    #[test]
    fn enforcement_script_is_a_bounded_convergence_loop() {
        let s = enforcement_script(("10.0.0.5", 8788), ("10.0.0.6", 8787), 45);

        // It loops — a single-sample script is exactly the bug.
        assert!(s.contains("while :"), "script must poll, not sample once");
        // Both assertions are re-tested EVERY iteration against the right
        // targets.
        assert!(s.contains("nc -z -w 2 10.0.0.5 8788"));
        assert!(s.contains("nc -z -w 2 10.0.0.6 8787"));
        // Success requires BOTH conditions in the SAME observation.
        assert!(s.contains("[ \"$pos\" = ok ] && [ \"$neg\" = blocked ]"));
        // The bound is the configured window, checked against observed time —
        // not a blind `sleep 45`.
        assert!(s.contains("end=$(( $(date +%s) + 45 ))"));
        assert!(
            !s.contains("sleep 45"),
            "the window must be a deadline on observations, not one blind sleep"
        );
        // Every iteration emits an observation line (the observable half).
        assert!(s.contains("echo \"obs $i t=$(date +%s) pos=$pos neg=$neg\""));
        // Fail-closed verdicts keep the original exit-code contract:
        // 3 = NotEnforced (negative still reachable), 2 = Unschedulable.
        assert!(s.contains("exit 3"));
        assert!(s.contains("exit 2"));
        assert!(s.contains("exit 0"));
        // The inter-observation pacing is a poll interval, not the bound.
        assert!(s.contains("sleep 1"));
    }

    /// The pod's own clock must strictly contain the observation window: a
    /// shorter activeDeadline would kill a still-observing probe and
    /// re-introduce the race as a flake.
    #[test]
    fn probe_pod_deadline_contains_the_observation_window() {
        let wait = 75u64;
        let pod = build_probe_pod(&cfg(), "probe-x", "busybox:1.36", "echo hi", wait);
        let deadline = pod["spec"]["activeDeadlineSeconds"].as_u64().unwrap();
        assert!(
            deadline > wait,
            "activeDeadlineSeconds ({deadline}) must exceed the observation window ({wait})"
        );
        assert_eq!(deadline, wait + PROBE_SCHEDULING_SLACK_SECS);
    }
}
