//! Pure Pod + Secret manifest assembly — no cluster I/O, so the shape
//! (env routing, security baseline, container topology) is unit-testable
//! without a kube-apiserver (this is the P3 mocked-kube tier's main target).

use crate::config::K8sConfig;
use fluidbox_core::traits::SandboxSpec;
use serde_json::{json, Value};

pub const LABEL_SESSION: &str = "fluidbox.dev/session";
pub const LABEL_MANAGED: &str = "fluidbox.dev/managed";
pub const RUNNER_CONTAINER: &str = "runner";
pub const COLLECTOR_CONTAINER: &str = "workspace-collector";
pub const INIT_CONTAINER: &str = "workspace-init";
/// The startup network-admission gate: FIRST init container when the spec
/// carries a `NetworkAdmission`. Init containers complete before app
/// containers start (kubelet contract), so the untrusted runner cannot
/// execute until this gate has OBSERVED the pod's own NetworkPolicy enforced
/// — closing the CNI fail-open window (AWS VPC CNI `standard` mode) during
/// which a fresh pod has unrestricted egress.
pub const NETPOL_GATE_CONTAINER: &str = "netpol-gate";
/// One Secret key per audience-scoped credential (Gap 10, invariant 19). The
/// runner container references control/tool/llm; the INIT container references
/// `workspace-token` and NOTHING else, so the archive-fetch credential never
/// enters the process the agent runs in.
pub const SECRET_TOKEN_KEY: &str = "session-token";
pub const SECRET_TOOL_TOKEN_KEY: &str = "tool-token";
pub const SECRET_LLM_TOKEN_KEY: &str = "llm-token";
pub const SECRET_WORKSPACE_TOKEN_KEY: &str = "workspace-token";

/// Deterministic per-run object name.
pub fn object_name(session_id: uuid::Uuid) -> String {
    format!("fluidbox-{session_id}")
}

/// Pod labels. `session` + `managed` have always been here; `tenant` and `run`
/// are the other two thirds of the identity a per-run network policy selects
/// on, and the selector is a SECURITY control — the Phase 0 spike showed that a
/// policy selecting a shared label pools every concurrent run's resolved FQDN
/// addresses into one reachable set. A pod that is missing them would simply
/// not be selected by its own policy, so it would run offline rather than
/// unrestricted; fail-closed, but still a bug.
fn labels(spec: &SandboxSpec) -> Value {
    let mut l = json!({
        LABEL_SESSION: spec.session_id.to_string(),
        LABEL_MANAGED: "true",
    });
    if let Some(g) = &spec.network_grant {
        l["fluidbox.dev/tenant"] = json!(g.tenant_id.to_string());
        l["fluidbox.dev/run"] = json!(g.run_id.to_string());
    }
    l
}

/// The per-run Secret carrying the FOUR audience-scoped session tokens — created
/// AFTER the Pod so its ownerReference can point at the Pod UID (GC reaps it
/// with the Pod). `immutable` locks it against tampering. One key per audience
/// so each container references exactly the credential it needs.
pub fn build_secret(spec: &SandboxSpec, pod_uid: &str) -> Value {
    let name = object_name(spec.session_id);
    let t = &spec.tokens;
    json!({
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": name,
            "labels": labels(spec),
            "ownerReferences": [{
                "apiVersion": "v1",
                "kind": "Pod",
                "name": name,
                "uid": pod_uid,
                "controller": false,
                "blockOwnerDeletion": false,
            }],
        },
        "type": "Opaque",
        "immutable": true,
        "stringData": {
            SECRET_TOKEN_KEY: t.control,
            SECRET_TOOL_TOKEN_KEY: t.tool,
            SECRET_LLM_TOKEN_KEY: t.llm,
            SECRET_WORKSPACE_TOKEN_KEY: t.workspace,
        },
    })
}

/// The one disposable execution object: init (fetch+unpack), runner
/// (unmodified harness image), collector (long-lived, diff-out). References
/// the not-yet-existing Secret so the kubelet holds container start until the
/// Secret lands (Pod-first/Secret-second — no orphan window, no patch step).
pub fn build_pod(spec: &SandboxSpec, cfg: &K8sConfig) -> Value {
    let name = object_name(spec.session_id);
    let secret_name = name.clone();
    let archive = spec.workspace_archive.as_ref();

    // Env routing: any var whose VALUE is one of the audience-scoped tokens rides
    // a secretKeyRef pointed at THAT audience's key (pods-read RBAC must not leak
    // a live token via PodSpec env); everything else is a plain literal. With four
    // distinct tokens the match must resolve per-audience, not to one shared key —
    // otherwise ANTHROPIC_API_KEY would silently serve the control credential.
    let mut plain_env: Vec<Value> = Vec::new();
    for (k, v) in &spec.env {
        match token_secret_key(spec, v) {
            Some(key) => plain_env.push(secret_ref_env(k, &secret_name, key)),
            None => plain_env.push(json!({ "name": k, "value": v })),
        }
    }

    let base_commit = archive
        .and_then(|a| a.base_commit.clone())
        .unwrap_or_default();

    let container_sc = json!({
        "allowPrivilegeEscalation": false,
        "capabilities": { "drop": ["ALL"] },
        "runAsNonRoot": true,
        "runAsUser": cfg.run_as_user,
    });

    let init_env = json!([
        { "name": "FLUIDBOX_WORKSPACE", "value": "/workspace" },
        { "name": "FLUIDBOX_COLLECTOR_DIR", "value": "/collector" },
        { "name": "FLUIDBOX_WORKSPACE_ARCHIVE_URL",
          "value": archive.map(|a| a.url.clone()).unwrap_or_default() },
        { "name": "FLUIDBOX_ARCHIVE_SHA256",
          "value": archive.map(|a| a.sha256.clone()).unwrap_or_default() },
        { "name": "FLUIDBOX_ARCHIVE_LEN",
          "value": archive.map(|a| a.len.to_string()).unwrap_or_default() },
        // Gap 10: the init container gets the WORKSPACE-audience token and
        // nothing else — it can fetch this run's archive and cannot touch
        // /permission, /events, /result, or the facade. The var NAME stays
        // FLUIDBOX_SESSION_TOKEN because that is what `workspaced init` reads;
        // only the credential behind it narrowed.
        secret_ref_env(
            "FLUIDBOX_SESSION_TOKEN",
            &secret_name,
            SECRET_WORKSPACE_TOKEN_KEY,
        ),
    ]);

    let collector_env = json!([
        { "name": "FLUIDBOX_WORKSPACE", "value": "/workspace" },
        { "name": "FLUIDBOX_COLLECTOR_DIR", "value": "/collector" },
        { "name": "FLUIDBOX_BASE_COMMIT", "value": base_commit },
    ]);

    // Init chain: the network-admission gate FIRST (when required), then the
    // workspace fetch. Ordering is deliberate: nothing — not even the trusted
    // archive fetch — runs until the pod's own network is proven enforced,
    // and the kubelet's init-container contract then keeps the untrusted
    // runner off the network for free.
    let mut init_containers: Vec<Value> = Vec::new();
    if let Some(adm) = &spec.network_admission {
        let script = crate::netpol::enforcement_script(
            (adm.positive_addr.as_str(), adm.positive_port),
            (adm.negative_addr.as_str(), adm.negative_port),
            adm.wait_secs,
        );
        init_containers.push(json!({
            "name": NETPOL_GATE_CONTAINER,
            "image": cfg.netpol_probe_image,
            "command": ["/bin/sh", "-c", script],
            "securityContext": container_sc,
            // Tiny and explicit: the gate must never inflate the pod's
            // effective request (quota) past the main containers.
            "resources": {
                "requests": { "cpu": "10m", "memory": "16Mi" },
                "limits": { "cpu": "200m", "memory": "64Mi" },
            },
        }));
    }
    init_containers.push(json!({
        "name": INIT_CONTAINER,
        "image": cfg.collector_image,
        "command": ["workspaced", "init"],
        "env": init_env,
        "securityContext": container_sc,
        "volumeMounts": [
            { "name": "workspace", "mountPath": "/workspace" },
            { "name": "collector", "mountPath": "/collector" },
        ],
    }));

    let mut pod_spec = json!({
        "restartPolicy": "Never",
        "automountServiceAccountToken": false,
        "enableServiceLinks": false,
        "activeDeadlineSeconds": active_deadline(spec, cfg),
        "securityContext": {
            "runAsNonRoot": true,
            "runAsUser": cfg.run_as_user,
            "runAsGroup": cfg.run_as_user,
            "fsGroup": cfg.run_as_user,
            "seccompProfile": { "type": "RuntimeDefault" },
        },
        "volumes": [
            { "name": "workspace", "emptyDir": { "sizeLimit": cfg.volume_size_limit } },
            { "name": "collector", "emptyDir": { "sizeLimit": cfg.volume_size_limit } },
        ],
        "initContainers": init_containers,
        "containers": [
            {
                "name": RUNNER_CONTAINER,
                "image": spec.image,
                "workingDir": "/workspace",
                "env": plain_env,
                "securityContext": container_sc,
                "resources": {
                    "requests": {
                        "cpu": cfg.cpu_request, "memory": cfg.mem_request,
                        "ephemeral-storage": cfg.ephemeral_request,
                    },
                    "limits": {
                        "cpu": cfg.cpu_limit, "memory": cfg.mem_limit,
                        "ephemeral-storage": cfg.ephemeral_limit,
                    },
                },
                "volumeMounts": [
                    { "name": "workspace", "mountPath": "/workspace" },
                ],
            },
            {
                "name": COLLECTOR_CONTAINER,
                "image": cfg.collector_image,
                "command": ["workspaced", "wait"],
                "env": collector_env,
                "securityContext": container_sc,
                "resources": {
                    "requests": { "cpu": "50m", "memory": "64Mi" },
                    "limits": { "cpu": "500m", "memory": "256Mi" },
                },
                "volumeMounts": [
                    { "name": "workspace", "mountPath": "/workspace", "readOnly": true },
                    { "name": "collector", "mountPath": "/collector" },
                ],
            },
        ],
    });

    // Route the sandbox at the CONTROLLED resolver.
    //
    // Without this the pod keeps the cluster default (kube-dns), which its
    // per-run policy does not allow — so an FQDN grant silently fails to
    // resolve while the policy itself verifies as perfectly Valid. That is the
    // worst kind of failure: everything reports healthy and nothing works.
    //
    // The controlled resolver is forward-only with NO `kubernetes` plugin, so a
    // sandbox cannot resolve in-cluster Service names even when its grant lets
    // it resolve public ones. Offline runs are pointed there too and simply get
    // no answer — they have no allow rule reaching it, which is exactly right.
    if !cfg.sandbox_dns_ip.is_empty() {
        pod_spec["dnsPolicy"] = json!("None");
        pod_spec["dnsConfig"] = json!({ "nameservers": [cfg.sandbox_dns_ip] });
    }

    apply_cluster_policy(&mut pod_spec, cfg);

    json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": { "name": name, "labels": labels(spec) },
        "spec": pod_spec,
    })
}

/// Cluster-policy scheduling + registry knobs shared by EVERY pod this
/// provider creates in the sandbox namespace (sandbox pods and the netpol
/// probe — the probe must land on the same pool or the gate certifies the
/// wrong nodes). Applied only when set, so unset knobs stay absent rather
/// than rendering as null/[].
pub(crate) fn apply_cluster_policy(pod_spec: &mut Value, cfg: &K8sConfig) {
    if let Some(rc) = &cfg.runtime_class_name {
        pod_spec["runtimeClassName"] = json!(rc);
    }
    if let Some(pc) = &cfg.priority_class_name {
        pod_spec["priorityClassName"] = json!(pc);
    }
    if !cfg.node_selector.is_empty() {
        let ns: serde_json::Map<String, Value> = cfg
            .node_selector
            .iter()
            .map(|(k, v)| (k.clone(), json!(v)))
            .collect();
        pod_spec["nodeSelector"] = Value::Object(ns);
    }
    if !cfg.tolerations.is_empty() {
        pod_spec["tolerations"] = json!(cfg
            .tolerations
            .iter()
            .map(|t| json!({
                "key": t.key, "operator": t.operator, "value": t.value, "effect": t.effect,
                "tolerationSeconds": t.toleration_seconds,
            }))
            .collect::<Vec<_>>());
    }
    // Private images: the referenced Secrets must exist in the SANDBOX
    // namespace (imagePullSecrets are namespace-local).
    if !cfg.image_pull_secrets.is_empty() {
        pod_spec["imagePullSecrets"] = json!(cfg
            .image_pull_secrets
            .iter()
            .map(|n| json!({ "name": n }))
            .collect::<Vec<_>>());
    }
}

fn active_deadline(spec: &SandboxSpec, cfg: &K8sConfig) -> i64 {
    match spec.active_deadline_secs {
        Some(b) => b as i64 + cfg.init_grace_secs,
        None => cfg.default_deadline_secs,
    }
}

fn secret_ref_env(name: &str, secret: &str, key: &str) -> Value {
    json!({
        "name": name,
        "valueFrom": { "secretKeyRef": { "name": secret, "key": key } },
    })
}

/// Which Secret key (if any) an env VALUE is — the per-audience successor to the
/// old single-token match. `workspace` is intentionally NOT considered here: it
/// never appears in the runner container's env, and the init container
/// references its key explicitly.
fn token_secret_key(spec: &SandboxSpec, value: &str) -> Option<&'static str> {
    let t = &spec.tokens;
    // An empty token would match every empty env value — never route those.
    if value.is_empty() {
        return None;
    }
    if value == t.control {
        Some(SECRET_TOKEN_KEY)
    } else if value == t.tool {
        Some(SECRET_TOOL_TOKEN_KEY)
    } else if value == t.llm {
        Some(SECRET_LLM_TOKEN_KEY)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fluidbox_core::traits::{NetworkMode, SandboxTokens, WorkspaceArchive};

    // The four audience tokens are DISTINCT values — that is what makes the
    // per-audience routing assertions below meaningful.
    const CONTROL: &str = "fbx_sess_control_secret";
    const TOOL: &str = "fbx_sess_tool_secret";
    const LLM: &str = "fbx_sess_llm_secret";
    const WORKSPACE: &str = "fbx_sess_workspace_secret";

    fn spec() -> SandboxSpec {
        SandboxSpec {
            session_id: uuid::Uuid::nil(),
            image: "ghcr.io/x/runner:dev".into(),
            env: vec![
                ("FLUIDBOX_SESSION_TOKEN".into(), CONTROL.into()),
                ("FLUIDBOX_TOOL_TOKEN".into(), TOOL.into()),
                ("ANTHROPIC_API_KEY".into(), LLM.into()),
                ("FLUIDBOX_TASK".into(), "do a thing".into()),
                ("FLUIDBOX_CONTROL_URL".into(), "http://svc:8788".into()),
            ],
            tokens: SandboxTokens {
                control: CONTROL.into(),
                tool: TOOL.into(),
                llm: LLM.into(),
                workspace: WORKSPACE.into(),
            },
            workspace_host_dir: None,
            workspace_archive: Some(WorkspaceArchive {
                url: "http://svc:8788/internal/sessions/x/workspace".into(),
                sha256: "sha256:abcd".into(),
                len: 1234,
                base_commit: Some("deadbeef".into()),
            }),
            active_deadline_secs: Some(600),
            network: NetworkMode::Hardened,
            network_admission: None,
            network_grant: None,
        }
    }

    fn admission() -> fluidbox_core::traits::NetworkAdmission {
        fluidbox_core::traits::NetworkAdmission {
            positive_addr: "10.96.0.10".into(),
            positive_port: 8788,
            negative_addr: "10.96.0.11".into(),
            negative_port: 8787,
            wait_secs: 60,
        }
    }

    fn cfg() -> K8sConfig {
        K8sConfig::from_env()
    }

    /// The sandbox must be POINTED at the controlled resolver, not merely
    /// allowed to reach it.
    ///
    /// This is the gap an adversarial review found: the per-run policy allowed
    /// :53 to the controlled CoreDNS, but the pod still used the cluster
    /// default (kube-dns) — which its policy does NOT allow. Every FQDN grant
    /// therefore failed to resolve while the policy verified as perfectly
    /// Valid. The kind validation missed it because its fixture pods set
    /// `dnsConfig` by hand and never exercised `build_pod`.
    #[test]
    fn a_sandbox_is_pointed_at_the_controlled_resolver() {
        let mut c = cfg();
        c.sandbox_dns_ip = "10.96.0.53".into();
        let pod = build_pod(&spec(), &c);
        assert_eq!(pod["spec"]["dnsPolicy"], "None");
        assert_eq!(pod["spec"]["dnsConfig"]["nameservers"][0], "10.96.0.53");

        // Unconfigured (grants disabled) leaves the cluster default alone, so
        // enabling this feature is what changes DNS — nothing else.
        let plain = build_pod(&spec(), &cfg());
        assert!(plain["spec"].get("dnsPolicy").is_none());
        assert!(plain["spec"].get("dnsConfig").is_none());
    }

    /// The resolver the per-run policy allows must be selected in the RELEASE
    /// namespace, which is NOT the sandbox namespace. Using the sandbox
    /// namespace selects nothing, and the failure is silent.
    #[test]
    fn the_resolver_selector_uses_the_release_namespace() {
        let mut c = cfg();
        c.namespace = "fluidbox-sandboxes".into();
        c.dns_namespace = "fluidbox".into();
        let labels = c.sandbox_resolver_labels();
        assert_eq!(labels["k8s:io.kubernetes.pod.namespace"], "fluidbox");
        assert_ne!(
            labels["k8s:io.kubernetes.pod.namespace"], "fluidbox-sandboxes",
            "selecting the sandbox namespace matches no resolver pod"
        );
    }

    /// The pod must carry all three labels its own network policy selects on.
    /// Missing them is fail-closed (the policy would not select the pod, so it
    /// would run offline rather than unrestricted) but still a bug, and a
    /// silent one — this catches it.
    #[test]
    fn the_pod_carries_the_network_identity_triple() {
        let tenant = uuid::Uuid::now_v7();
        let run = uuid::Uuid::now_v7();
        let mut s = spec();
        s.network_grant = Some(fluidbox_core::traits::GrantedNetwork {
            grant: fluidbox_core::network::NetworkGrant::offline(),
            tenant_id: tenant,
            run_id: run,
            grant_digest: "sha256:x".into(),
        });
        let pod = build_pod(&s, &cfg());
        let l = &pod["metadata"]["labels"];
        assert_eq!(l[LABEL_SESSION], s.session_id.to_string());
        assert_eq!(l["fluidbox.dev/tenant"], tenant.to_string());
        assert_eq!(l["fluidbox.dev/run"], run.to_string());
        assert_eq!(l[LABEL_MANAGED], "true");

        // A run with no grant (resolved before governed networking) keeps
        // exactly the labels it always had — no empty tenant/run keys that a
        // selector could accidentally match.
        let plain = build_pod(&spec(), &cfg());
        assert!(plain["metadata"]["labels"]
            .get("fluidbox.dev/tenant")
            .is_none());
    }

    #[test]
    fn each_audience_token_rides_its_own_secret_key_never_a_literal() {
        let pod = build_pod(&spec(), &cfg());
        let runner = &pod["spec"]["containers"][0];
        assert_eq!(runner["name"], RUNNER_CONTAINER);
        let env = runner["env"].as_array().unwrap();
        // Every credential var rides a secretKeyRef pointed at ITS OWN audience
        // key — a shared key would silently hand the control token to the model
        // client (the exact regression the split exists to prevent).
        for (var, key) in [
            ("FLUIDBOX_SESSION_TOKEN", SECRET_TOKEN_KEY),
            ("FLUIDBOX_TOOL_TOKEN", SECRET_TOOL_TOKEN_KEY),
            ("ANTHROPIC_API_KEY", SECRET_LLM_TOKEN_KEY),
        ] {
            let e = env.iter().find(|e| e["name"] == var).unwrap();
            assert!(e.get("value").is_none(), "{var} leaked a plaintext value");
            assert_eq!(
                e["valueFrom"]["secretKeyRef"]["key"], key,
                "{var} must resolve the {key} audience"
            );
        }
        // The runner container NEVER receives the workspace token, under any var.
        assert!(
            !env.iter().any(|e| e["name"] == "FLUIDBOX_WORKSPACE_TOKEN"
                || e["valueFrom"]["secretKeyRef"]["key"] == SECRET_WORKSPACE_TOKEN_KEY),
            "the workspace credential must not reach the runner container"
        );
        // A non-secret var stays a plain literal.
        let task = env.iter().find(|e| e["name"] == "FLUIDBOX_TASK").unwrap();
        assert_eq!(task["value"], "do a thing");
        // No token string of ANY audience appears anywhere in the serialized Pod.
        let ser = serde_json::to_string(&pod).unwrap();
        for tok in [CONTROL, TOOL, LLM, WORKSPACE] {
            assert!(!ser.contains(tok), "{tok} leaked into the Pod manifest");
        }
    }

    #[test]
    fn init_container_gets_only_the_workspace_token() {
        let pod = build_pod(&spec(), &cfg());
        let init = &pod["spec"]["initContainers"][0];
        assert_eq!(init["name"], INIT_CONTAINER);
        let env = init["env"].as_array().unwrap();
        // Exactly ONE credential reference, and it is the workspace audience.
        let refs: Vec<&Value> = env
            .iter()
            .filter(|e| e.get("valueFrom").is_some())
            .collect();
        assert_eq!(
            refs.len(),
            1,
            "init container must hold exactly one credential"
        );
        assert_eq!(refs[0]["name"], "FLUIDBOX_SESSION_TOKEN"); // what workspaced reads
        assert_eq!(
            refs[0]["valueFrom"]["secretKeyRef"]["key"], SECRET_WORKSPACE_TOKEN_KEY,
            "the init container's credential must be the workspace-audience token"
        );
        // The rest of the init env is plain archive metadata — no other secret.
        for key in [
            SECRET_TOKEN_KEY,
            SECRET_TOOL_TOKEN_KEY,
            SECRET_LLM_TOKEN_KEY,
        ] {
            assert!(
                !env.iter()
                    .any(|e| e["valueFrom"]["secretKeyRef"]["key"] == key),
                "init container must not reference {key}"
            );
        }
    }

    #[test]
    fn pod_carries_the_security_baseline() {
        let pod = build_pod(&spec(), &cfg());
        let sc = &pod["spec"]["securityContext"];
        assert_eq!(sc["runAsNonRoot"], true);
        assert_eq!(sc["runAsUser"], 10001);
        assert_eq!(sc["seccompProfile"]["type"], "RuntimeDefault");
        assert_eq!(pod["spec"]["automountServiceAccountToken"], false);
        assert_eq!(pod["spec"]["restartPolicy"], "Never");
        // activeDeadlineSeconds = budget (600) + init grace (300).
        assert_eq!(pod["spec"]["activeDeadlineSeconds"], 900);
        // Three container roles: init + runner + collector.
        assert_eq!(pod["spec"]["initContainers"].as_array().unwrap().len(), 1);
        assert_eq!(pod["spec"]["containers"].as_array().unwrap().len(), 2);
    }

    /// The netpol admission race fix: with a `NetworkAdmission` frozen into
    /// the spec, the gate init container runs FIRST — before the workspace
    /// fetch and (by the kubelet's init-container contract) before the
    /// untrusted runner — observing the pod's OWN network until enforcement
    /// holds, bounded and fail-closed.
    #[test]
    fn network_admission_gate_is_the_first_init_container() {
        let mut s = spec();
        s.network_admission = Some(admission());
        let pod = build_pod(&s, &cfg());
        let inits = pod["spec"]["initContainers"].as_array().unwrap();
        assert_eq!(inits.len(), 2, "gate + workspace-init");
        let gate = &inits[0];
        assert_eq!(gate["name"], NETPOL_GATE_CONTAINER);
        assert_eq!(
            inits[1]["name"], INIT_CONTAINER,
            "workspace fetch must run AFTER the gate"
        );
        // The gate runs the shared observation script against the frozen
        // targets — the same protocol the certification probe runs.
        let script = gate["command"][2].as_str().unwrap();
        assert!(script.contains("nc -z -w 2 10.96.0.10 8788"));
        assert!(script.contains("nc -z -w 2 10.96.0.11 8787"));
        assert!(script.contains("while :"), "the gate observes, not samples");
        assert!(script.contains("exit 3"), "fail-closed on not-enforced");
        // Restricted-PSS compliant like every other container.
        assert_eq!(gate["securityContext"]["allowPrivilegeEscalation"], false);
        assert_eq!(gate["securityContext"]["capabilities"]["drop"][0], "ALL");
        // The gate image is the probe image knob (busybox by default).
        assert_eq!(gate["image"], cfg().netpol_probe_image);
        // Tiny explicit resources: never the LimitRange defaults, never a
        // quota-relevant effective request.
        assert_eq!(gate["resources"]["requests"]["cpu"], "10m");
        // No volume mounts and no env: the gate needs the network only —
        // it must never see tokens or the workspace.
        assert!(gate.get("volumeMounts").is_none());
        assert!(gate.get("env").is_none());
    }

    /// Without a `NetworkAdmission` (dev posture / Docker parity) the pod
    /// shape is byte-identical to before the fix: one init container.
    #[test]
    fn no_admission_means_no_gate_container() {
        let pod = build_pod(&spec(), &cfg());
        let inits = pod["spec"]["initContainers"].as_array().unwrap();
        assert_eq!(inits.len(), 1);
        assert_eq!(inits[0]["name"], INIT_CONTAINER);
    }

    #[test]
    fn pod_tolerations_carry_toleration_seconds() {
        let mut c = cfg();
        c.tolerations = vec![crate::config::Toleration {
            key: Some("node.kubernetes.io/unreachable".into()),
            operator: Some("Exists".into()),
            value: None,
            effect: Some("NoExecute".into()),
            toleration_seconds: Some(120),
        }];
        let pod = build_pod(&spec(), &c);
        let t = &pod["spec"]["tolerations"][0];
        assert_eq!(t["effect"], "NoExecute");
        // A dropped tolerationSeconds would mean "tolerate forever".
        assert_eq!(t["tolerationSeconds"], 120);
    }

    #[test]
    fn pod_carries_image_pull_secrets_only_when_configured() {
        // Unset (the default env) → the field is absent entirely, not [].
        let pod = build_pod(&spec(), &cfg());
        assert!(pod["spec"].get("imagePullSecrets").is_none());

        let mut c = cfg();
        c.image_pull_secrets = vec!["regcred".into(), "mirror-cred".into()];
        let pod = build_pod(&spec(), &c);
        let refs = pod["spec"]["imagePullSecrets"].as_array().unwrap();
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0]["name"], "regcred");
        assert_eq!(refs[1]["name"], "mirror-cred");
    }

    #[test]
    fn secret_owner_reference_points_at_the_pod_uid() {
        let s = build_secret(&spec(), "pod-uid-123");
        assert_eq!(s["immutable"], true);
        let owner = &s["metadata"]["ownerReferences"][0];
        assert_eq!(owner["kind"], "Pod");
        assert_eq!(owner["uid"], "pod-uid-123");
        assert_eq!(owner["controller"], false);
        // One key per audience, each carrying its OWN credential.
        assert_eq!(s["stringData"][SECRET_TOKEN_KEY], CONTROL);
        assert_eq!(s["stringData"][SECRET_TOOL_TOKEN_KEY], TOOL);
        assert_eq!(s["stringData"][SECRET_LLM_TOKEN_KEY], LLM);
        assert_eq!(s["stringData"][SECRET_WORKSPACE_TOKEN_KEY], WORKSPACE);
        assert_eq!(
            s["stringData"].as_object().unwrap().len(),
            4,
            "exactly four audience keys"
        );
    }
}
