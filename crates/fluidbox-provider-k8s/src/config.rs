//! Provider configuration — all cluster-policy knobs (namespace, images,
//! isolation class, resources, security baseline). Never RunSpec/agent input:
//! `runtimeClassName` and friends come from the deployment, not the run.

/// The sandbox Pod security + scheduling baseline, portable to any conformant
/// cluster (design 2026-07-15, §"Sandbox pod security baseline").
#[derive(Debug, Clone)]
pub struct K8sConfig {
    /// The dedicated sandbox namespace (and ONLY that namespace — adoption
    /// refuses anything else).
    pub namespace: String,
    /// The `workspaced` collector image (init + collector containers).
    pub collector_image: String,
    /// Hard-isolation runtime class (gVisor/Kata), cluster-selected. None =
    /// the runc tier (documented as a real but lower tier).
    pub runtime_class_name: Option<String>,
    /// Numeric non-root uid (kubelet cannot prove a named USER is non-root).
    pub run_as_user: i64,
    /// `activeDeadlineSeconds` fallback for budget-less runs.
    pub default_deadline_secs: i64,
    /// Grace added to a run's wall-clock budget for init + teardown.
    pub init_grace_secs: i64,
    pub cpu_request: String,
    pub mem_request: String,
    pub cpu_limit: String,
    pub mem_limit: String,
    pub ephemeral_request: String,
    pub ephemeral_limit: String,
    /// `emptyDir.sizeLimit` for the workspace + collector volumes.
    pub volume_size_limit: String,
    /// Node scheduling hints applied to every sandbox Pod (values-driven).
    pub node_selector: Vec<(String, String)>,
    pub tolerations: Vec<Toleration>,
    pub priority_class_name: Option<String>,
    /// `imagePullSecrets` names for private runner/collector/probe images in
    /// the sandbox namespace (the Secret must exist there).
    pub image_pull_secrets: Vec<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct Toleration {
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub operator: Option<String>,
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub effect: Option<String>,
    /// Bounded-`NoExecute` support: dropping this on the floor would turn
    /// "tolerate for N seconds" into "tolerate forever".
    #[serde(default, rename = "tolerationSeconds")]
    pub toleration_seconds: Option<i64>,
}

impl K8sConfig {
    /// Build from the process environment (Helm sets these). Defaults are the
    /// design's documented baseline.
    pub fn from_env() -> Self {
        let get = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        Self {
            namespace: get("FLUIDBOX_K8S_NAMESPACE").unwrap_or_else(|| "fluidbox-sandboxes".into()),
            collector_image: get("FLUIDBOX_COLLECTOR_IMAGE")
                .unwrap_or_else(|| "ghcr.io/hrishikeshdkakkad/fluidbox-workspaced:dev".into()),
            runtime_class_name: get("FLUIDBOX_K8S_RUNTIME_CLASS"),
            run_as_user: get("FLUIDBOX_K8S_RUN_AS_USER")
                .and_then(|v| v.parse().ok())
                .unwrap_or(10001),
            default_deadline_secs: get("FLUIDBOX_K8S_DEFAULT_DEADLINE_SECS")
                .and_then(|v| v.parse().ok())
                .unwrap_or(3 * 3600),
            init_grace_secs: get("FLUIDBOX_K8S_INIT_GRACE_SECS")
                .and_then(|v| v.parse().ok())
                .unwrap_or(300),
            cpu_request: get("FLUIDBOX_K8S_CPU_REQUEST").unwrap_or_else(|| "500m".into()),
            mem_request: get("FLUIDBOX_K8S_MEM_REQUEST").unwrap_or_else(|| "1Gi".into()),
            cpu_limit: get("FLUIDBOX_K8S_CPU_LIMIT").unwrap_or_else(|| "2".into()),
            mem_limit: get("FLUIDBOX_K8S_MEM_LIMIT").unwrap_or_else(|| "2Gi".into()),
            ephemeral_request: get("FLUIDBOX_K8S_EPHEMERAL_REQUEST")
                .unwrap_or_else(|| "1Gi".into()),
            ephemeral_limit: get("FLUIDBOX_K8S_EPHEMERAL_LIMIT").unwrap_or_else(|| "10Gi".into()),
            volume_size_limit: get("FLUIDBOX_K8S_VOLUME_SIZE_LIMIT")
                .unwrap_or_else(|| "10Gi".into()),
            node_selector: parse_kv(get("FLUIDBOX_K8S_NODE_SELECTOR")),
            tolerations: parse_tolerations(get("FLUIDBOX_K8S_TOLERATIONS")),
            priority_class_name: get("FLUIDBOX_K8S_PRIORITY_CLASS"),
            image_pull_secrets: parse_list(get("FLUIDBOX_K8S_IMAGE_PULL_SECRETS")),
        }
    }
}

/// Parse `k1=v1,k2=v2` into pairs (node selector labels).
fn parse_kv(s: Option<String>) -> Vec<(String, String)> {
    let Some(s) = s else { return Vec::new() };
    s.split(',')
        .filter_map(|p| p.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect()
}

/// Parse a comma-separated list into trimmed, non-empty names
/// (`imagePullSecrets`).
fn parse_list(s: Option<String>) -> Vec<String> {
    let Some(s) = s else { return Vec::new() };
    s.split(',')
        .map(|x| x.trim().to_string())
        .filter(|x| !x.is_empty())
        .collect()
}

/// Parse `tolerations` from a JSON array of
/// `{key,operator,value,effect,tolerationSeconds}` objects — the shape Helm
/// produces from `values.sandbox.tolerations` via `toJson`, and the exact
/// shape `build_pod` serializes back. Salvaging: each element parses
/// independently, so ONE malformed toleration is warned about and skipped
/// instead of silently erasing the whole list (the placement is advisory
/// scheduling, not security — never a boot crash, but never silent either).
fn parse_tolerations(s: Option<String>) -> Vec<Toleration> {
    let Some(s) = s.filter(|v| !v.trim().is_empty()) else {
        return Vec::new();
    };
    let elements: Vec<serde_json::Value> = match serde_json::from_str(&s) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("FLUIDBOX_K8S_TOLERATIONS is not a JSON array ({e}); ignoring it");
            return Vec::new();
        }
    };
    elements
        .into_iter()
        .filter_map(
            |el| match serde_json::from_value::<Toleration>(el.clone()) {
                Ok(t) => Some(t),
                Err(e) => {
                    tracing::warn!("skipping malformed toleration {el} ({e})");
                    None
                }
            },
        )
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tolerations_parse_from_json_array() {
        let json = r#"[
            {"key":"dedicated","operator":"Equal","value":"fluidbox","effect":"NoSchedule"},
            {"operator":"Exists","effect":"NoExecute","tolerationSeconds":300}
        ]"#;
        let t = parse_tolerations(Some(json.to_string()));
        assert_eq!(t.len(), 2);
        assert_eq!(t[0].key.as_deref(), Some("dedicated"));
        assert_eq!(t[0].value.as_deref(), Some("fluidbox"));
        assert_eq!(t[0].effect.as_deref(), Some("NoSchedule"));
        assert_eq!(t[0].toleration_seconds, None);
        assert_eq!(t[1].key, None);
        assert_eq!(t[1].operator.as_deref(), Some("Exists"));
        // tolerationSeconds survives the round-trip: dropping it would turn a
        // BOUNDED NoExecute toleration into "tolerate forever" (Codex round 2).
        assert_eq!(t[1].toleration_seconds, Some(300));
    }

    #[test]
    fn tolerations_empty_or_garbage_is_empty() {
        assert!(parse_tolerations(None).is_empty());
        assert!(parse_tolerations(Some("   ".into())).is_empty());
        assert!(parse_tolerations(Some("not json".into())).is_empty());
    }

    #[test]
    fn tolerations_salvage_valid_elements_from_a_partly_bad_list() {
        // One malformed element (numeric value — invalid per the K8s API)
        // must not silently erase the OTHER, valid tolerations.
        let json = r#"[
            {"key":"dedicated","operator":"Equal","value":"fluidbox","effect":"NoSchedule"},
            {"key":"bad","operator":"Equal","value":7,"effect":"NoSchedule"}
        ]"#;
        let t = parse_tolerations(Some(json.to_string()));
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].key.as_deref(), Some("dedicated"));
    }

    #[test]
    fn pull_secrets_parse_comma_list() {
        assert_eq!(parse_list(Some("a, b ,c".into())), vec!["a", "b", "c"]);
        assert!(parse_list(Some(" , ".into())).is_empty());
        assert!(parse_list(None).is_empty());
    }
}
