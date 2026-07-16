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
}

#[derive(Debug, Clone)]
pub struct Toleration {
    pub key: Option<String>,
    pub operator: Option<String>,
    pub value: Option<String>,
    pub effect: Option<String>,
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
            tolerations: Vec::new(),
            priority_class_name: get("FLUIDBOX_K8S_PRIORITY_CLASS"),
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
