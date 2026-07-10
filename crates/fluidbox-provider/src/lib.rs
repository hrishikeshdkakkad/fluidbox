//! fluidbox-provider — the Docker ExecutionProvider (M1).
//!
//! Sandboxes are plain containers, labelled so a boot-time sweep can reap
//! orphans. The `SandboxHandle` persisted to the DB carries only the
//! container id + network name, so the control plane can reattach after a
//! restart. Workspace materialization is done control-plane-side (see
//! `workspace`); the container only ever sees a copy bind-mounted at
//! /workspace.

use async_trait::async_trait;
use bollard::models::{ContainerCreateBody, HostConfig, NetworkCreateRequest};
use bollard::query_parameters::{
    CreateContainerOptionsBuilder, InspectContainerOptions, ListContainersOptionsBuilder,
    RemoveContainerOptionsBuilder,
};
use bollard::Docker;
use fluidbox_core::traits::{
    ExecutionProvider, NetworkMode, ProviderError, SandboxHandle, SandboxSpec, SandboxState,
};
use std::collections::HashMap;
use uuid::Uuid;

pub mod workspace;

const SESSION_LABEL: &str = "fluidbox.session";
const MANAGED_LABEL: &str = "fluidbox.managed";

pub struct DockerProvider {
    docker: Docker,
}

impl DockerProvider {
    pub fn connect() -> anyhow::Result<Self> {
        let docker = Docker::connect_with_local_defaults()?;
        Ok(Self { docker })
    }

    pub async fn ping(&self) -> anyhow::Result<()> {
        self.docker.ping().await?;
        Ok(())
    }

    async fn ensure_network(&self, name: &str, internal: bool) -> Result<(), ProviderError> {
        // Idempotent: ignore "already exists".
        let req = NetworkCreateRequest {
            name: name.to_string(),
            driver: Some("bridge".to_string()),
            internal: Some(internal),
            attachable: Some(true),
            ..Default::default()
        };
        match self.docker.create_network(req).await {
            Ok(_) => Ok(()),
            Err(e) if e.to_string().contains("already exists") => Ok(()),
            Err(e) => Err(ProviderError::Other(format!("create_network: {e}"))),
        }
    }
}

fn map_err(e: impl std::fmt::Display) -> ProviderError {
    ProviderError::Other(e.to_string())
}

#[async_trait]
impl ExecutionProvider for DockerProvider {
    async fn provision(&self, spec: &SandboxSpec) -> Result<SandboxHandle, ProviderError> {
        let name = format!("fluidbox-{}", spec.session_id);
        let net_name = format!("fluidbox-net-{}", spec.session_id);

        let internal = matches!(spec.network, NetworkMode::Hardened);
        self.ensure_network(&net_name, internal).await?;

        let env: Vec<String> = spec.env.iter().map(|(k, v)| format!("{k}={v}")).collect();

        let mut labels = HashMap::new();
        labels.insert(SESSION_LABEL.to_string(), spec.session_id.to_string());
        labels.insert(MANAGED_LABEL.to_string(), "1".to_string());

        let mut binds = Vec::new();
        if let Some(dir) = &spec.workspace_host_dir {
            binds.push(format!("{dir}:/workspace:rw"));
        }

        // host-dev mode needs host.docker.internal to reach the control
        // plane; hardened mode attaches the control plane to the bridge
        // instead (that wiring lands with the hardened-compose path).
        let extra_hosts = match spec.network {
            NetworkMode::HostDev => Some(vec!["host.docker.internal:host-gateway".to_string()]),
            NetworkMode::Hardened => None,
        };

        let host_config = HostConfig {
            binds: if binds.is_empty() { None } else { Some(binds) },
            network_mode: Some(net_name.clone()),
            auto_remove: Some(false), // we reap explicitly so we can collect the diff
            extra_hosts,
            memory: Some(2 * 1024 * 1024 * 1024),
            pids_limit: Some(512),
            cap_drop: Some(vec!["ALL".to_string()]),
            security_opt: Some(vec!["no-new-privileges".to_string()]),
            ..Default::default()
        };

        let body = ContainerCreateBody {
            image: Some(spec.image.clone()),
            env: Some(env),
            labels: Some(labels),
            working_dir: Some("/workspace".to_string()),
            host_config: Some(host_config),
            ..Default::default()
        };

        let opts = CreateContainerOptionsBuilder::new().name(&name).build();
        let created = self
            .docker
            .create_container(Some(opts), body)
            .await
            .map_err(map_err)?;

        self.docker
            .start_container(
                &created.id,
                None::<bollard::query_parameters::StartContainerOptions>,
            )
            .await
            .map_err(map_err)?;

        Ok(SandboxHandle {
            runtime: "docker".to_string(),
            external_id: created.id,
            attrs: serde_json::json!({ "network": net_name, "name": name }),
        })
    }

    async fn state(&self, handle: &SandboxHandle) -> Result<SandboxState, ProviderError> {
        match self
            .docker
            .inspect_container(&handle.external_id, None::<InspectContainerOptions>)
            .await
        {
            Ok(info) => {
                let st = info.state.unwrap_or_default();
                if st.running.unwrap_or(false) {
                    Ok(SandboxState::Running)
                } else {
                    Ok(SandboxState::Exited(st.exit_code.unwrap_or(0)))
                }
            }
            Err(e) if e.to_string().contains("No such container") => Ok(SandboxState::Gone),
            Err(e) => Err(map_err(e)),
        }
    }

    async fn terminate(&self, handle: &SandboxHandle) -> Result<(), ProviderError> {
        let opts = RemoveContainerOptionsBuilder::new()
            .force(true)
            .v(true)
            .build();
        match self
            .docker
            .remove_container(&handle.external_id, Some(opts))
            .await
        {
            Ok(_) => {}
            Err(e) if e.to_string().contains("No such container") => {}
            Err(e) => return Err(map_err(e)),
        }
        if let Some(net) = handle.attrs.get("network").and_then(|v| v.as_str()) {
            let _ = self.docker.remove_network(net).await;
        }
        Ok(())
    }

    async fn list_orphans(&self) -> Result<Vec<(Uuid, SandboxHandle)>, ProviderError> {
        let mut filters: HashMap<String, Vec<String>> = HashMap::new();
        filters.insert("label".to_string(), vec![format!("{MANAGED_LABEL}=1")]);
        let opts = ListContainersOptionsBuilder::new()
            .all(true)
            .filters(&filters)
            .build();
        let containers = self
            .docker
            .list_containers(Some(opts))
            .await
            .map_err(map_err)?;
        let mut out = Vec::new();
        for c in containers {
            let labels = c.labels.unwrap_or_default();
            let Some(sid) = labels
                .get(SESSION_LABEL)
                .and_then(|s| Uuid::parse_str(s).ok())
            else {
                continue;
            };
            let net = c
                .network_settings
                .and_then(|ns| ns.networks)
                .and_then(|m| m.into_keys().next())
                .unwrap_or_default();
            out.push((
                sid,
                SandboxHandle {
                    runtime: "docker".to_string(),
                    external_id: c.id.unwrap_or_default(),
                    attrs: serde_json::json!({ "network": net }),
                },
            ));
        }
        Ok(out)
    }

    fn runtime_name(&self) -> &'static str {
        "docker"
    }
}
