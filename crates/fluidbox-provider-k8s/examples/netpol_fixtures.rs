//! Validation fixture generator: prints the PRODUCTION netpol artifacts —
//! the enforcement observation script, the certification probe Pod, and a
//! sandbox Pod carrying the `netpol-gate` init container — so live-cluster
//! validation (scripts/netpol-admission-validation.sh) exercises the real
//! bytes this crate ships, not a hand-copied approximation that could drift.
//!
//! Never part of a release build (examples are dev-only targets).

use fluidbox_core::traits::{NetworkAdmission, NetworkMode, SandboxSpec, SandboxTokens};
use fluidbox_provider_k8s::config::K8sConfig;
use fluidbox_provider_k8s::{manifest, netpol};

fn usage() -> ! {
    eprintln!(
        "usage:\n  netpol_fixtures script <pos_addr> <pos_port> <neg_addr> <neg_port> <wait_secs>\n  \
         netpol_fixtures probe-pod <name> <image> <pos_addr> <pos_port> <neg_addr> <neg_port> <wait_secs>\n  \
         netpol_fixtures sandbox-pod <pos_addr> <pos_port> <neg_addr> <neg_port> <wait_secs>\n\
         sandbox-pod reads the K8s knobs from the environment (FLUIDBOX_K8S_*, \
         FLUIDBOX_NETPOL_PROBE_IMAGE, FLUIDBOX_COLLECTOR_IMAGE) and RUNNER_IMAGE."
    );
    std::process::exit(2);
}

fn admission(args: &[String]) -> NetworkAdmission {
    NetworkAdmission {
        positive_addr: args[0].clone(),
        positive_port: args[1].parse().expect("positive port"),
        negative_addr: args[2].clone(),
        negative_port: args[3].parse().expect("negative port"),
        wait_secs: args[4].parse().expect("wait secs"),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(|s| s.as_str()) {
        Some("script") if args.len() == 6 => {
            let a = admission(&args[1..]);
            println!(
                "{}",
                netpol::enforcement_script(
                    (a.positive_addr.as_str(), a.positive_port),
                    (a.negative_addr.as_str(), a.negative_port),
                    a.wait_secs,
                )
            );
        }
        Some("probe-pod") if args.len() == 8 => {
            let (name, image) = (&args[1], &args[2]);
            let a = admission(&args[3..]);
            let script = netpol::enforcement_script(
                (a.positive_addr.as_str(), a.positive_port),
                (a.negative_addr.as_str(), a.negative_port),
                a.wait_secs,
            );
            let pod =
                netpol::build_probe_pod(&K8sConfig::from_env(), name, image, &script, a.wait_secs);
            println!("{}", serde_json::to_string_pretty(&pod).unwrap());
        }
        Some("sandbox-pod") if args.len() == 6 => {
            let a = admission(&args[1..]);
            let spec = SandboxSpec {
                session_id: uuid::Uuid::nil(),
                image: std::env::var("RUNNER_IMAGE").unwrap_or_else(|_| "busybox:1.36".into()),
                env: vec![("FLUIDBOX_TASK".into(), "netpol-validation".into())],
                tokens: SandboxTokens {
                    control: "fbx_sess_stub_control".into(),
                    tool: "fbx_sess_stub_tool".into(),
                    llm: "fbx_sess_stub_llm".into(),
                    workspace: "fbx_sess_stub_workspace".into(),
                },
                workspace_host_dir: None,
                workspace_archive: None,
                active_deadline_secs: Some(600),
                network: NetworkMode::Hardened,
                network_admission: Some(a),
                network_grant: None,
            };
            let pod = manifest::build_pod(&spec, &K8sConfig::from_env());
            println!("{}", serde_json::to_string_pretty(&pod).unwrap());
        }
        _ => usage(),
    }
}
