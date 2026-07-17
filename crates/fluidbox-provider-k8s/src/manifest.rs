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
pub const SECRET_TOKEN_KEY: &str = "session-token";

/// Deterministic per-run object name.
pub fn object_name(session_id: uuid::Uuid) -> String {
    format!("fluidbox-{session_id}")
}

fn labels(session_id: uuid::Uuid) -> Value {
    json!({
        LABEL_SESSION: session_id.to_string(),
        LABEL_MANAGED: "true",
    })
}

/// The per-run Secret carrying the session token — created AFTER the Pod so
/// its ownerReference can point at the Pod UID (GC reaps it with the Pod).
/// `immutable` locks it against tampering.
pub fn build_secret(spec: &SandboxSpec, pod_uid: &str) -> Value {
    let name = object_name(spec.session_id);
    let token = session_token(spec).unwrap_or_default();
    json!({
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": name,
            "labels": labels(spec.session_id),
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
        "stringData": { SECRET_TOKEN_KEY: token },
    })
}

/// The one disposable execution object: init (fetch+unpack), runner
/// (unmodified harness image), collector (long-lived, diff-out). References
/// the not-yet-existing Secret so the kubelet holds container start until the
/// Secret lands (Pod-first/Secret-second — no orphan window, no patch step).
pub fn build_pod(spec: &SandboxSpec, cfg: &K8sConfig) -> Value {
    let name = object_name(spec.session_id);
    let secret_name = name.clone();
    let token = session_token(spec);
    let archive = spec.workspace_archive.as_ref();

    // Env routing: anything whose VALUE is the session token rides a
    // secretKeyRef (pods-read RBAC must not leak a live token via PodSpec env);
    // everything else is a plain literal.
    let mut plain_env: Vec<Value> = Vec::new();
    for (k, v) in &spec.env {
        if token.as_deref() == Some(v.as_str()) {
            plain_env.push(secret_ref_env(k, &secret_name, SECRET_TOKEN_KEY));
        } else {
            plain_env.push(json!({ "name": k, "value": v }));
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
        secret_ref_env("FLUIDBOX_SESSION_TOKEN", &secret_name, SECRET_TOKEN_KEY),
    ]);

    let collector_env = json!([
        { "name": "FLUIDBOX_WORKSPACE", "value": "/workspace" },
        { "name": "FLUIDBOX_COLLECTOR_DIR", "value": "/collector" },
        { "name": "FLUIDBOX_BASE_COMMIT", "value": base_commit },
    ]);

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
        "initContainers": [{
            "name": INIT_CONTAINER,
            "image": cfg.collector_image,
            "command": ["workspaced", "init"],
            "env": init_env,
            "securityContext": container_sc,
            "volumeMounts": [
                { "name": "workspace", "mountPath": "/workspace" },
                { "name": "collector", "mountPath": "/collector" },
            ],
        }],
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

    apply_cluster_policy(&mut pod_spec, cfg);

    json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": { "name": name, "labels": labels(spec.session_id) },
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

fn session_token(spec: &SandboxSpec) -> Option<String> {
    spec.env
        .iter()
        .find(|(k, _)| k == "FLUIDBOX_SESSION_TOKEN")
        .map(|(_, v)| v.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fluidbox_core::traits::{NetworkMode, WorkspaceArchive};

    fn spec() -> SandboxSpec {
        SandboxSpec {
            session_id: uuid::Uuid::nil(),
            image: "ghcr.io/x/runner:dev".into(),
            env: vec![
                ("FLUIDBOX_SESSION_TOKEN".into(), "fbx_sess_secret".into()),
                ("ANTHROPIC_API_KEY".into(), "fbx_sess_secret".into()),
                ("FLUIDBOX_TASK".into(), "do a thing".into()),
                ("FLUIDBOX_CONTROL_URL".into(), "http://svc:8788".into()),
            ],
            workspace_host_dir: None,
            workspace_archive: Some(WorkspaceArchive {
                url: "http://svc:8788/internal/sessions/x/workspace".into(),
                sha256: "sha256:abcd".into(),
                len: 1234,
                base_commit: Some("deadbeef".into()),
            }),
            active_deadline_secs: Some(600),
            network: NetworkMode::Hardened,
        }
    }

    fn cfg() -> K8sConfig {
        K8sConfig::from_env()
    }

    #[test]
    fn token_never_appears_as_a_plain_pod_env_literal() {
        let pod = build_pod(&spec(), &cfg());
        let runner = &pod["spec"]["containers"][0];
        assert_eq!(runner["name"], RUNNER_CONTAINER);
        let env = runner["env"].as_array().unwrap();
        // Both the token var AND the anthropic key (same value) ride
        // secretKeyRef; NEITHER carries a plaintext `value`.
        for key in ["FLUIDBOX_SESSION_TOKEN", "ANTHROPIC_API_KEY"] {
            let e = env.iter().find(|e| e["name"] == key).unwrap();
            assert!(e.get("value").is_none(), "{key} leaked a plaintext value");
            assert_eq!(e["valueFrom"]["secretKeyRef"]["key"], SECRET_TOKEN_KEY);
        }
        // A non-secret var stays a plain literal.
        let task = env.iter().find(|e| e["name"] == "FLUIDBOX_TASK").unwrap();
        assert_eq!(task["value"], "do a thing");
        // The whole serialized Pod must not contain the token string anywhere.
        assert!(!serde_json::to_string(&pod)
            .unwrap()
            .contains("fbx_sess_secret"));
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
        assert_eq!(s["stringData"][SECRET_TOKEN_KEY], "fbx_sess_secret");
    }
}
