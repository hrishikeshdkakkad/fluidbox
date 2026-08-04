//! The Cilium implementation of [`NetworkPolicyProvider`] — the half that talks
//! to a cluster. The pure lowering lives in [`crate::netgrant`].
//!
//! ## What `verify()` can and cannot prove
//!
//! The plan originally had this read `CiliumEndpoint.status.policy` for
//! `realized` / `policy-enabled` / `policy-revision`. The Phase 0 spike
//! falsified that: on Cilium 1.19.x `status.policy` is EMPTY, and the
//! `endpointStatus` Helm knob that used to populate it no longer exists in the
//! chart (`helm show values cilium/cilium --version 1.19.6 | grep
//! endpointStatus` returns nothing). The enforcement fact does exist, but only
//! node-locally through the agent's own CLI — reachable solely by `exec`ing into
//! the DaemonSet, a privilege the control plane must not take.
//!
//! So this is honest about its scope. It proves two things over the k8s API:
//!
//! 1. **The policy was ACCEPTED.** A structurally invalid policy is rejected by
//!    CRD schema validation at the `create` call itself — a hard error with no
//!    window in which a bad policy sits silently pending, which is a *better*
//!    fail-closed signal than any status poll. Semantic acceptance then shows up
//!    as `status.conditions[type=Valid]` from the Cilium operator.
//! 2. **The pod has a real security identity**, and one derived from labels that
//!    include this run's — so the policy's `endpointSelector` has something
//!    specific to bind to.
//!
//! It does **not** prove datapath realization, and nothing available over the
//! k8s API on 1.19.x does. Realization is proven from inside the pod's own
//! network namespace by the `netpol-gate` init container, which observes the
//! positive target reachable and the negative target blocked before any
//! untrusted code runs. **Both must hold**; either failing is fail-closed. This
//! is the belt, that is the braces, and the docs say so rather than implying
//! this check is stronger than it is.

use crate::netgrant::{self, LABEL_SESSION};
use fluidbox_core::traits::{GrantedNetwork, NetworkPolicyError, NetworkPolicyProvider};
use k8s_openapi::api::core::v1::Pod;
use kube::api::{Api, ApiResource, DeleteParams, DynamicObject};
use kube::Client;
use serde_json::Value;
use std::time::{Duration, Instant};

/// How often to re-ask while waiting for the operator and the CNI to catch up.
/// Both are fast (sub-second in practice); this is a poll floor, not a sleep.
const POLL_INTERVAL: Duration = Duration::from_millis(500);

/// The `cilium.io/v2` resources this enforcer touches. Dynamic rather than
/// typed: the CRDs have no Rust binding, and vendoring one for a handful of
/// fields would be a schema we then have to keep in step with Cilium's.
pub fn cnp_resource() -> ApiResource {
    ApiResource {
        group: "cilium.io".into(),
        version: "v2".into(),
        api_version: "cilium.io/v2".into(),
        kind: "CiliumNetworkPolicy".into(),
        plural: "ciliumnetworkpolicies".into(),
    }
}

pub fn cep_resource() -> ApiResource {
    ApiResource {
        group: "cilium.io".into(),
        version: "v2".into(),
        api_version: "cilium.io/v2".into(),
        kind: "CiliumEndpoint".into(),
        plural: "ciliumendpoints".into(),
    }
}

pub struct CiliumNetworkEnforcer {
    cnps: Api<DynamicObject>,
    ceps: Api<DynamicObject>,
    pods: Api<Pod>,
    namespace: String,
    /// Bound on how long `verify` waits for the operator to mark the policy
    /// valid and the CNI to give the pod an identity. Reuses the deployment's
    /// existing NetworkPolicy convergence budget rather than inventing a second
    /// knob for the same physical wait (AWS VPC CNI lands ~20 s; Cilium is much
    /// faster, but the ceiling belongs to the operator, not to us).
    verify_timeout_secs: u64,
    /// Labels selecting the controlled resolver a per-run policy may allow.
    resolver_labels: Value,
}

impl CiliumNetworkEnforcer {
    pub fn new(
        client: Client,
        namespace: String,
        verify_timeout_secs: u64,
        resolver_labels: Value,
    ) -> Self {
        Self {
            cnps: Api::namespaced_with(client.clone(), &namespace, &cnp_resource()),
            ceps: Api::namespaced_with(client.clone(), &namespace, &cep_resource()),
            pods: Api::namespaced(client, &namespace),
            namespace,
            verify_timeout_secs,
            resolver_labels,
        }
    }

    /// Can this deployment actually use CiliumNetworkPolicy? The `auto`
    /// detection, and the precondition check for explicit `cilium`.
    ///
    /// Probed by LISTING the resource in our own namespace rather than reading
    /// the discovery document, because that answers the question we actually
    /// care about: not "does the CRD exist somewhere" but "can we read and
    /// therefore write the objects this enforcer depends on". An enforcer we
    /// lack RBAC for is not an enforcer, and treating it as one would admit
    /// grants that fail at provision.
    ///
    /// The two failure causes are logged distinctly — a missing CRD is a
    /// cluster without Cilium, a 403 is a chart/RBAC misconfiguration — because
    /// they need completely different fixes.
    pub async fn detect(client: &Client, namespace: &str) -> bool {
        let cnps: Api<DynamicObject> =
            Api::namespaced_with(client.clone(), namespace, &cnp_resource());
        match cnps.list(&kube::api::ListParams::default().limit(1)).await {
            Ok(_) => true,
            Err(kube::Error::Api(e)) if e.code == 404 => {
                tracing::debug!("cilium.io/v2 CiliumNetworkPolicy is not served by this cluster");
                false
            }
            Err(kube::Error::Api(e)) if e.code == 403 => {
                tracing::warn!(
                    "cilium.io/v2 exists but this ServiceAccount may not list \
                     CiliumNetworkPolicy ({}). The chart grants it when \
                     networkGrants.enabled=true — without it the deployment is offline-only.",
                    e.message
                );
                false
            }
            Err(e) => {
                tracing::warn!("probing for CiliumNetworkPolicy failed: {e}");
                false
            }
        }
    }

    /// The per-run objects are named after the session, which is also the pod's
    /// name — `GrantedNetwork::run_id` IS the session id (stamped in the
    /// orchestrator), so one identifier addresses the pod, the policy, and the
    /// endpoint.
    fn object_name(g: &GrantedNetwork) -> String {
        crate::manifest::object_name(g.run_id)
    }

    /// The condition the Cilium operator sets once it has accepted a policy
    /// semantically. Absent means "not yet"; `False` means rejected.
    fn policy_is_valid(obj: &DynamicObject) -> Option<bool> {
        let conditions = obj.data.get("status")?.get("conditions")?.as_array()?;
        conditions
            .iter()
            .find(|c| c.get("type").and_then(|t| t.as_str()) == Some("Valid"))
            .and_then(|c| c.get("status").and_then(|s| s.as_str()))
            .map(|s| s == "True")
    }

    /// A CiliumEndpoint is usable when it is `ready` AND carries a concrete
    /// security identity. The identity is what a policy's `endpointSelector`
    /// binds to, so an endpoint without one has nothing for the policy to
    /// select — it would run under whatever the cluster-wide baseline says,
    /// which is default-deny, but it is not the state we asked for.
    fn endpoint_identity(obj: &DynamicObject) -> Option<i64> {
        let status = obj.data.get("status")?;
        if status.get("state").and_then(|s| s.as_str()) != Some("ready") {
            return None;
        }
        status.get("identity")?.get("id")?.as_i64()
    }
}

#[async_trait::async_trait]
impl NetworkPolicyProvider for CiliumNetworkEnforcer {
    /// Write the per-run policy, owned by the pod.
    ///
    /// The pod's UID is read here rather than threaded through the trait: it
    /// keeps [`NetworkPolicyProvider`] free of Kubernetes concepts, and the pod
    /// provably exists by now because the caller creates it first.
    async fn prepare(&self, granted: &GrantedNetwork) -> Result<(), NetworkPolicyError> {
        // EXPIRY FENCE. The orchestrator checks the grant once, before workspace
        // materialization and archive packing — both of which can take minutes.
        // Without this check the following sequence resurrects dead authority
        // PERMANENTLY:
        //
        //   1. the grant expires while provisioning is still in flight
        //   2. the expiry sweeper deletes the not-yet-created policy (404 = ok)
        //   3. it marks the row `revoked`
        //   4. provisioning continues and creates the policy from the frozen spec
        //   5. the sweeper never looks at that row again — it is already revoked
        //
        // …leaving an allow policy created AFTER expiry and living until
        // terminal cleanup. The frozen grant carries its own absolute expiry, so
        // this needs no database read and cannot race the sweeper: a policy is
        // simply never created for authority that has already lapsed.
        if granted.grant.is_expired(chrono::Utc::now()) {
            return Err(NetworkPolicyError::Unverified(format!(
                "the network grant for run {} expired before enforcement could be \
                 programmed — refusing to create a policy for lapsed authority",
                granted.run_id
            )));
        }
        if !granted.grant.grants_egress() {
            // Offline is the ABSENCE of an allow, delivered by the chart-static
            // baseline's default-deny. Writing an empty policy would be noise,
            // and a hazard if "empty egress" ever gained a permissive reading.
            return Ok(());
        }
        let name = Self::object_name(granted);
        let pod = self
            .pods
            .get(&name)
            .await
            .map_err(|e| NetworkPolicyError::Write(format!("pod {name} not found: {e}")))?;
        let uid = pod
            .metadata
            .uid
            .clone()
            .ok_or_else(|| NetworkPolicyError::Write(format!("pod {name} has no uid")))?;

        let ctx = netgrant::PolicyContext {
            namespace: self.namespace.clone(),
            resolver_labels: self.resolver_labels.clone(),
            owner_pod_uid: uid,
            owner_pod_name: name.clone(),
        };
        let Some(policy) = netgrant::build_run_policy(granted, granted.run_id, &ctx) else {
            return Ok(());
        };
        let obj: DynamicObject = serde_json::from_value(policy)
            .map_err(|e| NetworkPolicyError::Lowering(format!("bad policy manifest: {e}")))?;

        match self.cnps.create(&Default::default(), &obj).await {
            Ok(_) => Ok(()),
            // Already there. `prepare` must stay idempotent — a retried
            // provision cannot fail on its own previous success — but it must
            // NOT blindly adopt whatever object holds the name: a stale or
            // foreign policy under the deterministic session name would be
            // accepted, and `verify` only checks that the NAMED policy is
            // Valid, so a broader one would sail through.
            //
            // The comparison is the RENDERED SPEC, not the grant digest. The
            // digest commits to the AUTHORIZATION INTENT, not to the object
            // that enforces it — so a policy rendered from the same grant by an
            // OLDER build carries an identical digest while permitting more.
            // Not hypothetical: when DNS lowering was tightened from
            // `matchPattern: "*"` to the granted names, both renderings shared
            // a digest, and a digest-only check would have adopted the
            // permissive one. Byte-comparing the spec is what actually means
            // "this is the object we would have written".
            Err(kube::Error::Api(e)) if e.code == 409 => {
                let existing = self.cnps.get(&name).await.map_err(|e| {
                    NetworkPolicyError::Write(format!("re-reading the existing policy failed: {e}"))
                })?;
                if existing.data.get("spec") == obj.data.get("spec") {
                    Ok(())
                } else {
                    Err(NetworkPolicyError::Write(format!(
                        "a different network policy already exists under the name for run {} — \
                         its spec is not the one this run would write, so it is refused rather \
                         than adopted",
                        granted.run_id
                    )))
                }
            }
            Err(e) => Err(NetworkPolicyError::Write(format!(
                "creating the network policy for run {} failed: {e}",
                granted.run_id
            ))),
        }
    }

    /// Prove — over the k8s API only — that the policy was accepted and the pod
    /// has an identity for it to bind to. See the module docs for exactly what
    /// this does and does not establish.
    async fn verify(&self, granted: &GrantedNetwork) -> Result<(), NetworkPolicyError> {
        // The second expiry fence. `verify` runs after `prepare` and before the
        // Secret that releases the pod, so a grant that lapses in between is
        // caught here and the run never starts. (The provision path deletes the
        // pod on a verify failure, and the policy is owned by that pod.)
        if granted.grant.is_expired(chrono::Utc::now()) {
            return Err(NetworkPolicyError::Unverified(format!(
                "the network grant for run {} expired during provisioning",
                granted.run_id
            )));
        }
        let name = Self::object_name(granted);
        let deadline = Instant::now() + Duration::from_secs(self.verify_timeout_secs.max(5));
        // Carried out of the loop so a timeout can say WHICH half never
        // converged — "unverified" with no detail is a support ticket.
        let mut policy_state = "not created";
        let mut endpoint_state = "no endpoint";

        loop {
            // An offline run has no policy object, so only the identity half
            // applies: there is still a pod that must be a real endpoint under
            // the default-deny baseline.
            let policy_ok = if granted.grant.grants_egress() {
                match self.cnps.get_opt(&name).await {
                    Ok(Some(obj)) => match Self::policy_is_valid(&obj) {
                        Some(true) => true,
                        Some(false) => {
                            // The operator REJECTED it. Waiting cannot help, so
                            // fail immediately rather than burning the deadline.
                            return Err(NetworkPolicyError::Unverified(format!(
                                "Cilium rejected the network policy for run {} \
                                 (status.conditions[Valid]=False)",
                                granted.run_id
                            )));
                        }
                        None => {
                            policy_state = "accepted, awaiting operator validation";
                            false
                        }
                    },
                    Ok(None) => {
                        policy_state = "not created";
                        false
                    }
                    Err(e) => {
                        return Err(NetworkPolicyError::Unverified(format!(
                            "reading the network policy for run {} failed: {e}",
                            granted.run_id
                        )))
                    }
                }
            } else {
                policy_state = "n/a (offline)";
                true
            };

            let identity_ok = match self.ceps.get_opt(&name).await {
                Ok(Some(obj)) => match Self::endpoint_identity(&obj) {
                    Some(id) => {
                        // No state assignment: the success path returns before
                        // the timeout message that reads it.
                        tracing::debug!(run_id = %granted.run_id, identity = id, "endpoint identity");
                        true
                    }
                    None => {
                        endpoint_state = "endpoint exists but is not ready / has no identity";
                        false
                    }
                },
                Ok(None) => {
                    endpoint_state = "no endpoint";
                    false
                }
                Err(e) => {
                    return Err(NetworkPolicyError::Unverified(format!(
                        "reading the Cilium endpoint for run {} failed: {e}",
                        granted.run_id
                    )))
                }
            };

            if policy_ok && identity_ok {
                return Ok(());
            }
            if Instant::now() >= deadline {
                // FAIL CLOSED. An unproven policy is treated exactly like a
                // refused one — the run does not start.
                return Err(NetworkPolicyError::Unverified(format!(
                    "network enforcement for run {} was not verified within {}s \
                     (policy: {policy_state}; endpoint: {endpoint_state})",
                    granted.run_id, self.verify_timeout_secs
                )));
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }

    async fn revoke(&self, granted: &GrantedNetwork) -> Result<(), NetworkPolicyError> {
        let name = Self::object_name(granted);
        // Delete only what belongs to THIS run — two independent checks,
        // because they answer different questions.
        //
        // OWNERSHIP: the object must carry our run's session label. A uid
        // precondition alone authenticates the object we just read, not that it
        // is ours; so if `prepare` refused a foreign object under the
        // deterministic name, terminal cleanup would then delete that very
        // object — turning a refusal into somebody else's outage.
        //
        // ATOMICITY: the uid precondition then makes the API server enforce
        // that we delete the object we inspected, closing the delete/recreate
        // window between the read and the delete.
        let existing = match self.cnps.get_opt(&name).await {
            Ok(Some(o)) => o,
            Ok(None) => return Ok(()),
            Err(e) => {
                return Err(NetworkPolicyError::Write(format!(
                    "reading the network policy for run {} before delete failed: {e}",
                    granted.run_id
                )))
            }
        };
        let ours = existing
            .metadata
            .labels
            .as_ref()
            .and_then(|l| l.get(LABEL_SESSION))
            .map(|v| v == &granted.run_id.to_string())
            .unwrap_or(false);
        if !ours {
            tracing::warn!(
                run_id = %granted.run_id,
                "a network policy exists under this run's name but is not labelled as ours; \
                 leaving it alone rather than deleting another owner's object"
            );
            return Ok(());
        }
        let dp = DeleteParams {
            preconditions: existing.metadata.uid.map(|u| kube::api::Preconditions {
                uid: Some(u),
                resource_version: None,
            }),
            ..DeleteParams::default()
        };
        match self.cnps.delete(&name, &dp).await {
            Ok(_) => Ok(()),
            // Already gone — owner-reference GC may have collected it first.
            // Idempotence matters: this runs from terminal cleanup, the abandon
            // paths, and the reconcile sweep.
            Err(kube::Error::Api(e)) if e.code == 404 => Ok(()),
            // The object was REPLACED between our read and the delete. This is
            // NOT success: a replacement is still standing, and reporting Ok
            // would let the caller mark the grant revoked — after which the
            // expiry sweeper never revisits the row and the replacement leaks
            // as an additive Cilium allow. Erroring makes the caller retry,
            // which re-reads and re-evaluates ownership.
            Err(kube::Error::Api(e)) if e.code == 409 => Err(NetworkPolicyError::Write(format!(
                "the network policy for run {} was replaced while being deleted; retrying",
                granted.run_id
            ))),
            Err(e) => Err(NetworkPolicyError::Write(format!(
                "deleting the network policy for run {} failed: {e}",
                granted.run_id
            ))),
        }
    }

    fn enforcer_name(&self) -> &'static str {
        "cilium"
    }

    fn supports_egress_grants(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn obj(v: serde_json::Value) -> DynamicObject {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn policy_validity_reads_the_operators_condition() {
        // Accepted.
        assert_eq!(
            CiliumNetworkEnforcer::policy_is_valid(&obj(json!({
                "apiVersion": "cilium.io/v2", "kind": "CiliumNetworkPolicy",
                "metadata": {"name": "x"},
                "status": {"conditions": [
                    {"type": "Valid", "status": "True", "message": "Policy validation succeeded"}
                ]}
            }))),
            Some(true)
        );
        // REJECTED — distinct from "not yet", because waiting cannot fix it.
        assert_eq!(
            CiliumNetworkEnforcer::policy_is_valid(&obj(json!({
                "apiVersion": "cilium.io/v2", "kind": "CiliumNetworkPolicy",
                "metadata": {"name": "x"},
                "status": {"conditions": [{"type": "Valid", "status": "False"}]}
            }))),
            Some(false)
        );
        // Not yet judged: no status, empty status, or another condition only.
        for v in [
            json!({"apiVersion":"cilium.io/v2","kind":"CiliumNetworkPolicy","metadata":{"name":"x"}}),
            json!({"apiVersion":"cilium.io/v2","kind":"CiliumNetworkPolicy","metadata":{"name":"x"},"status":{}}),
            json!({"apiVersion":"cilium.io/v2","kind":"CiliumNetworkPolicy","metadata":{"name":"x"},
                   "status":{"conditions":[{"type":"Other","status":"True"}]}}),
        ] {
            assert_eq!(CiliumNetworkEnforcer::policy_is_valid(&obj(v)), None);
        }
    }

    #[test]
    fn endpoint_identity_requires_ready_and_a_real_id() {
        // The shape observed on a live 1.19.6 cluster during the Phase 0 spike.
        assert_eq!(
            CiliumNetworkEnforcer::endpoint_identity(&obj(json!({
                "apiVersion": "cilium.io/v2", "kind": "CiliumEndpoint",
                "metadata": {"name": "fluidbox-x"},
                "status": {"state": "ready", "identity": {"id": 39493}}
            }))),
            Some(39493)
        );
        // Not ready yet → not usable, even with an identity.
        assert_eq!(
            CiliumNetworkEnforcer::endpoint_identity(&obj(json!({
                "apiVersion": "cilium.io/v2", "kind": "CiliumEndpoint",
                "metadata": {"name": "fluidbox-x"},
                "status": {"state": "waiting-for-identity", "identity": {"id": 39493}}
            }))),
            None
        );
        // Ready but no identity → nothing for an endpointSelector to bind to.
        assert_eq!(
            CiliumNetworkEnforcer::endpoint_identity(&obj(json!({
                "apiVersion": "cilium.io/v2", "kind": "CiliumEndpoint",
                "metadata": {"name": "fluidbox-x"},
                "status": {"state": "ready"}
            }))),
            None
        );
        // The EMPTY `status.policy` the Phase 0 spike found on 1.19.x must NOT
        // be what this reads — an endpoint with a ready state and an identity
        // verifies even though `status.policy` is `{}`, which is exactly the
        // situation on every 1.19.x cluster.
        assert_eq!(
            CiliumNetworkEnforcer::endpoint_identity(&obj(json!({
                "apiVersion": "cilium.io/v2", "kind": "CiliumEndpoint",
                "metadata": {"name": "fluidbox-x"},
                "status": {"state": "ready", "identity": {"id": 1}, "policy": {}}
            }))),
            Some(1)
        );
    }
}
