//! Live check of the Cilium enforcer against a real cluster.
//!
//! The unit tests in `enforcer.rs` pin the SHAPES this code reads, taken from a
//! real 1.19.6 cluster. They cannot prove that `detect`, `prepare` and `verify`
//! actually work against an API server — that a policy we build is accepted,
//! that the endpoint we poll for appears, and above all that `verify` FAILS
//! CLOSED when enforcement is absent. Only a cluster can prove those.
//!
//! Driven by `scripts/netgrant-kind-validation.sh`; run directly with an
//! ambient kubeconfig:
//!
//! ```sh
//! cargo run -p fluidbox-provider-k8s --example enforcer_live -- <namespace>
//! ```
//!
//! Exits non-zero on the first failed assertion.

use fluidbox_core::network::{
    FqdnPattern, L4Protocol, NetworkGrant, NetworkGrantMode, PortSpec, TargetRule, SCHEMA_VERSION,
};
use fluidbox_core::traits::{GrantedNetwork, NetworkPolicyError, NetworkPolicyProvider};
use fluidbox_provider_k8s::enforcer::CiliumNetworkEnforcer;
use k8s_openapi::api::core::v1::Pod;
use kube::api::{Api, DeleteParams, PostParams};
use kube::Client;
use serde_json::json;

static mut PASS: u32 = 0;
static mut FAIL: u32 = 0;

fn ok(msg: &str) {
    println!("  \x1b[1;32m✓\x1b[0m {msg}");
    unsafe { PASS += 1 }
}
fn no(msg: &str) {
    println!("  \x1b[1;31m✗\x1b[0m {msg}");
    unsafe { FAIL += 1 }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // kube-rs (rustls 0.23) needs a process-level CryptoProvider chosen
    // explicitly — the workspace has more than one backend in tree, so without
    // this the Kubernetes client panics on its first TLS handshake. Same line
    // `main.rs` carries, for the same reason.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let ns = std::env::args().nth(1).unwrap_or_else(|| "netgrant".into());
    let client = Client::try_default().await?;
    let pods: Api<Pod> = Api::namespaced(client.clone(), &ns);

    println!("\n\x1b[1;36m== ENFORCER (live) — detect, prepare, verify, revoke ==\x1b[0m");

    // ── detect ────────────────────────────────────────────────────────────
    //
    // `--expect-absent` is the NEGATIVE CONTROL, run on the Calico cluster: a
    // detector that returned true unconditionally would sail through every
    // positive assertion below, so the only honest guard is a cluster that
    // genuinely has no Cilium. (A bogus NAMESPACE is not such a guard —
    // listing a CRD in a namespace that does not exist returns an empty list,
    // not a 404, because the resource TYPE is cluster-wide. Asserting on that
    // tested Kubernetes' namespace semantics, not ours.)
    let expect_absent = std::env::args().any(|a| a == "--expect-absent");
    let found = CiliumNetworkEnforcer::detect(&client, &ns).await;
    if expect_absent {
        if found {
            no("detect() claims Cilium on a cluster that does not have it");
        } else {
            ok("detect() correctly reports NO enforcer on a non-Cilium cluster");
        }
        // Nothing else is meaningful here: the whole point is that this
        // deployment is offline-only.
        let (p, f) = unsafe { (PASS, FAIL) };
        println!("  \x1b[1;32m{p} passed\x1b[0m, \x1b[1;31m{f} failed\x1b[0m (enforcer)");
        if f > 0 {
            std::process::exit(1);
        }
        return Ok(());
    }
    if found {
        ok("detect() finds CiliumNetworkPolicy on a Cilium cluster");
    } else {
        no("detect() should find CiliumNetworkPolicy here");
    }

    let enforcer = CiliumNetworkEnforcer::new(
        client.clone(),
        ns.clone(),
        20,
        json!({
            "k8s:io.kubernetes.pod.namespace": ns,
            "app.kubernetes.io/component": "sandbox-dns",
        }),
    );

    // ── verify() must FAIL CLOSED with nothing programmed ─────────────────
    //
    // The single most important assertion here: if this returned Ok for a run
    // with no pod and no policy, every other check in the suite would be
    // meaningless, because verify would be rubber-stamping.
    let orphan = granted(uuid::Uuid::now_v7(), NetworkGrantMode::Approved);
    match enforcer.verify(&orphan).await {
        Err(NetworkPolicyError::Unverified(m)) => {
            ok("verify() FAILS CLOSED when nothing is programmed");
            println!("      ({})", m.lines().next().unwrap_or("").trim());
        }
        Err(e) => no(&format!("expected Unverified, got a different error: {e}")),
        Ok(()) => no("verify() returned Ok with NOTHING programmed — it is rubber-stamping"),
    }

    // ── prepare + verify on a real pod ────────────────────────────────────
    let run_id = uuid::Uuid::now_v7();
    let g = granted(run_id, NetworkGrantMode::Approved);
    let name = format!("fluidbox-{run_id}");
    let pod: Pod = serde_json::from_value(json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": name,
            "labels": {
                "fluidbox.dev/managed": "true",
                "fluidbox.dev/session": run_id.to_string(),
                "fluidbox.dev/tenant": g.tenant_id.to_string(),
                "fluidbox.dev/run": run_id.to_string(),
            }
        },
        "spec": {
            "tolerations": [{"operator": "Exists"}],
            "containers": [{"name": "p", "image": "busybox:1.36", "command": ["sleep", "300"]}]
        }
    }))?;
    pods.create(&PostParams::default(), &pod).await?;
    ok(&format!("created pod {name}"));

    match enforcer.prepare(&g).await {
        Ok(()) => ok("prepare() wrote the per-run CiliumNetworkPolicy"),
        Err(e) => no(&format!("prepare() failed: {e}")),
    }
    // Idempotent: a retried provision must not fail on its own prior success.
    match enforcer.prepare(&g).await {
        Ok(()) => ok("…and is idempotent (a retry does not fail on AlreadyExists)"),
        Err(e) => no(&format!("prepare() is not idempotent: {e}")),
    }

    match enforcer.verify(&g).await {
        Ok(()) => ok("verify() proves the policy is Valid and the endpoint has an identity"),
        Err(e) => no(&format!(
            "verify() failed on a correctly programmed run: {e}"
        )),
    }

    // ── revoke, and its idempotence ───────────────────────────────────────
    match enforcer.revoke(&g).await {
        Ok(()) => ok("revoke() deleted the policy"),
        Err(e) => no(&format!("revoke() failed: {e}")),
    }
    match enforcer.revoke(&g).await {
        Ok(()) => ok("…and is idempotent (a second revoke is not an error)"),
        Err(e) => no(&format!("revoke() is not idempotent: {e}")),
    }
    // After revocation, verify must fail again — proving it reads live state
    // rather than caching its earlier success.
    match enforcer.verify(&g).await {
        Err(NetworkPolicyError::Unverified(_)) => {
            ok("verify() fails again after revoke (it reads live state, not a cached verdict)")
        }
        Err(e) => no(&format!("expected Unverified after revoke, got: {e}")),
        Ok(()) => no("verify() still returns Ok after the policy was revoked"),
    }

    // ── an EXPIRED grant must never be programmed ─────────────────────────
    //
    // The critical regression. Provisioning checks the grant ONCE, before
    // workspace materialization; if it expires during that window the sweeper
    // deletes a not-yet-created policy, marks the row revoked, and then
    // provisioning creates the policy anyway — resurrecting dead authority
    // until terminal cleanup, because the sweeper never revisits a revoked row.
    let mut expired = granted(run_id, NetworkGrantMode::Approved);
    expired.grant = serde_json::from_value(json!({
        "schema_version": 1,
        "mode": "approved",
        "targets": expired.grant.targets,
        "expires_at": "2000-01-01T00:00:00Z",
        "policy_digest": "sha256:live",
    }))?;
    match enforcer.prepare(&expired).await {
        Err(NetworkPolicyError::Unverified(_)) => {
            ok("prepare() REFUSES an expired grant (no policy for lapsed authority)")
        }
        Err(e) => no(&format!(
            "expected Unverified for an expired grant, got: {e}"
        )),
        Ok(()) => no("prepare() programmed a policy for an EXPIRED grant"),
    }
    match enforcer.verify(&expired).await {
        Err(NetworkPolicyError::Unverified(_)) => ok("…and verify() refuses it too"),
        Err(e) => no(&format!("expected Unverified, got: {e}")),
        Ok(()) => no("verify() passed an expired grant"),
    }
    // Nothing was written under that name.
    match enforcer.revoke(&expired).await {
        Ok(()) => ok("…and nothing was left behind to clean up"),
        Err(e) => no(&format!("revoke after a refused prepare failed: {e}")),
    }

    // ── an OFFLINE grant needs no policy but still needs an endpoint ──────
    let off = granted(run_id, NetworkGrantMode::Offline);
    match enforcer.prepare(&off).await {
        Ok(()) => ok("prepare() writes NO policy for an offline grant"),
        Err(e) => no(&format!("offline prepare() should be a no-op: {e}")),
    }
    match enforcer.verify(&off).await {
        Ok(()) => ok("verify() passes an offline grant on the endpoint check alone"),
        Err(e) => no(&format!("offline verify() failed: {e}")),
    }

    let _ = pods.delete(&name, &DeleteParams::default()).await;

    let (p, f) = unsafe { (PASS, FAIL) };
    println!("  \x1b[1;32m{p} passed\x1b[0m, \x1b[1;31m{f} failed\x1b[0m (enforcer)");
    if f > 0 {
        std::process::exit(1);
    }
    Ok(())
}

fn granted(run_id: uuid::Uuid, mode: NetworkGrantMode) -> GrantedNetwork {
    let targets = if mode == NetworkGrantMode::Approved {
        vec![TargetRule::dns(
            FqdnPattern::Wildcard {
                suffix: "example.com".into(),
            },
            vec![PortSpec::single(443)],
            L4Protocol::Tcp,
        )]
    } else {
        vec![]
    };
    let grant: NetworkGrant = serde_json::from_value(json!({
        "schema_version": SCHEMA_VERSION,
        "mode": mode.as_str(),
        "targets": targets,
        "expires_at": "2099-01-01T00:00:00Z",
        "policy_digest": "sha256:live",
    }))
    .expect("grant fixture");
    GrantedNetwork {
        grant,
        tenant_id: uuid::Uuid::nil(),
        run_id,
        grant_digest: "sha256:live".into(),
    }
}
