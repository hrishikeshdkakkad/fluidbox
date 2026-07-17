# Session handover — live EKS acceptance for the K8s provider (post-v0.2.0)

You're closing the LAST checkbox of the fluidbox Kubernetes-native-provider
epic (#48) at /Users/hrishikeshkakkad/Documents/infra: a live EKS acceptance
run + a fully AUDITED teardown. Everything else is DONE: PR #47 merged to
main (0ad2e8b), all 30 review findings fixed
(docs/reviews/2026-07-16-pr47-k8s-review-findings.md), v0.2.0 released —
5 multi-arch images on GHCR and the chart verified at
oci://ghcr.io/hrishikeshdkakkad/charts/fluidbox (version=appVersion=0.2.0).
kind+Calico CI is green; the design doc's acceptance bar requires ONE managed
cloud. Read CLAUDE.md + the design doc
(docs/plans/2026-07-15-kubernetes-native-provider-design.md) acceptance
section first. scripts/eks-teardown.sh (untracked) is a starting point.

NON-NEGOTIABLE:
- TEARDOWN SAFETY IS THE POINT. This was deferred solely so it runs with
  budget headroom. Before creating ANYTHING: write down every resource class
  you will create (EKS cluster, nodegroups, VPC/CF stacks, EBS vols, ELBs,
  ENIs, addons). After teardown: prove ZERO orphans via aws CLI audit
  (CloudFormation stacks deleted, no leftover LoadBalancers/volumes/ENIs).
  Never end the session with the cluster up and unattended.
- Never `source .env`, never run DB/e2e tests unprompted (just loads .env →
  real Neon). Build with: export CARGO_TARGET_DIR=$PWD/target
  CARGO_INCREMENTAL=0; cargo fmt/clippy/test only if code changes.
- Docker provider must stay untouched. main is PR-only: branch + PR
  (`gh pr merge --admin`); ALWAYS `git branch --show-current` first.
- Keep spend tiny: haiku only (FLUIDBOX_DEFAULT_MODEL=claude-haiku-4-5),
  smallest viable nodegroup (2× t3.medium ok), delete promptly.

PLAN:
1. Preflight: aws sts get-caller-identity; pick region; check quotas.
2. Cluster: eksctl create (or existing script), THEN the two traps from
   values/eks.yaml — (a) NetworkPolicy is NOT enforced by default: enable the
   VPC CNI network-policy agent (aws-node ENABLE_NETWORK_POLICY=true) or
   install Calico; (b) EBS CSI addon + IRSA, gp3 StorageClass, else the
   archive PVC stays Pending.
3. Secrets: kubectl create ns fluidbox; fluidbox-secrets with DATABASE_URL
   (Neon DIRECT — ask the user or read .env yourself ONLY for this secret,
   never source it), FLUIDBOX_ADMIN_TOKEN, FLUIDBOX_CREDENTIAL_KEY (32-byte
   hex), LITELLM_MASTER_KEY (+ ANTHROPIC_API_KEY if litellm.enabled=true —
   simplest for an isolated acceptance).
4. Install: helm install fluidbox
   oci://ghcr.io/hrishikeshdkakkad/charts/fluidbox --version 0.2.0
   -n fluidbox -f deploy/helm/fluidbox/values/eks.yaml
   --set litellm.enabled=true. Wait ready.
5. Certify: helm test fluidbox -n fluidbox MUST pass (+:8788 −:8787); server
   log shows "netpol gate: enforcement verified". If NotEnforced → fix CNI,
   never disable requireEnforced.
6. Acceptance = demo A on the provider: port-forward :8787, create agent
   (haiku), POST a run; verify pod lifecycle in fluidbox-sandboxes (init
   pulls archive → runner → collector), timeline streams, approval
   pause/resume works, terminal diff + cost recorded, pod+Secret GC'd.
   Capture evidence (kubectl outputs, run JSON) into
   docs/reviews/2026-07-17-eks-acceptance.md.
7. TEARDOWN: helm uninstall, delete PVC/namespaces, then cluster
   (eksctl delete), then the aws audit above. Record audit output in the
   evidence doc.
8. Wrap: PR the evidence doc + tick the acceptance boxes in the findings doc
   + design doc; close EPIC #48 (+ phase issues); delete stale handover docs
   (2026-07-16 fix/continuance, this file); update memory.

After this epic: multi-user MCP control plane (EPIC #28, design finalized,
branch release/multi-user-mcp-control-plane) — do NOT start unprompted.
