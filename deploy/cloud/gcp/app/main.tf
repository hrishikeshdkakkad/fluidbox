# ── Self-managed Cilium (cilium_mode = "upstream" only) ─────────────────────
#
# Installed here rather than by the fluidbox chart because it is CLUSTER
# infrastructure: it owns the CNI, every other workload depends on it, and the
# nodes stay tainted (`agentNotReadyTaintKey`, fed from the platform stack) until
# it removes the taint.
# Nothing else can schedule before this succeeds.
#
# Why at all: GKE Dataplane V2 exposes only CiliumClusterwideNetworkPolicy,
# while fluidbox's per-run enforcer writes NAMESPACED CiliumNetworkPolicy.
# Upstream Cilium provides both. Verified on a probe cluster before adoption -
# a namespaced CNP carrying toFQDNs was accepted with Valid=True.
#
# The GKE-specific values are not optional decoration:
#   nodeinit.*        prepares each node - mounts the eBPF filesystem, puts
#                     kubelet in CNI mode, removes Google's cbr0 bridge. GKE
#                     re-instates the stock CNI on upgrade/reboot, so this runs
#                     for the life of the cluster, not just at install.
#   cni.binPath       GKE keeps CNI binaries in /home/kubernetes/bin, not the
#                     usual /opt/cni/bin.
#   ipam.mode         `kubernetes` uses the per-node PodCIDRs GKE already
#                     allocates from the VPC-native secondary range.
resource "helm_release" "cilium" {
  count = var.cilium_mode == "upstream" ? 1 : 0

  name       = "cilium"
  repository = "https://helm.cilium.io/"
  chart      = "cilium"
  version    = var.cilium_chart_version
  namespace  = "kube-system"

  set {
    name  = "nodeinit.enabled"
    value = "true"
  }
  set {
    name  = "nodeinit.reconfigureKubelet"
    value = "true"
  }
  set {
    name  = "nodeinit.removeCbrBridge"
    value = "true"
  }
  set {
    name  = "cni.binPath"
    value = "/home/kubernetes/bin"
  }
  set {
    name  = "gke.enabled"
    value = "true"
  }
  set {
    name  = "ipam.mode"
    value = "kubernetes"
  }
  set {
    name  = "ipv4NativeRoutingCIDR"
    value = var.pods_cidr
  }
  # The key the operator removes once a node is prepared. Must be the key the
  # node pools are born with - fed from the platform output, never retyped -
  # and must carry the cluster-autoscaler ignore-taint prefix, or a
  # scale-to-zero pool can never scale up (see platform/gke.tf).
  set {
    name  = "agentNotReadyTaintKey"
    value = var.cilium_agent_not_ready_taint_key
  }

  # NOT atomic: a rollback here would uninstall the CNI from a running cluster,
  # which is far worse than a half-installed one an operator can inspect.
  atomic          = false
  cleanup_on_fail = false
  wait            = true
  timeout         = 900
}

# ── Priority: the control plane outranks the work it governs ────────────────
#
# Without this, the scheduler treats a sandbox pod and the control plane as
# equals. On a lean single-node system pool that is a real failure mode: a
# burst of sandboxes fills the node, the control plane gets evicted, and every
# in-flight run loses the thing that was supposed to govern it.
#
# preemption_policy Never on the sandbox class is the other half. Sandboxes may
# WAIT for capacity - the run queue is built for exactly that - but they must
# never evict anything to get it.

resource "kubernetes_priority_class_v1" "control_plane" {
  metadata {
    name = "fluidbox-control-plane"
  }
  value          = 1000000
  global_default = false
  description    = "Control plane, LiteLLM, and anything else whose loss ends every run at once."
}

resource "kubernetes_priority_class_v1" "sandbox" {
  metadata {
    name = "fluidbox-sandbox"
  }
  value             = 1000
  global_default    = false
  preemption_policy = "Never"
  description       = "Agent sandboxes. Queue for capacity; never take it from anything else."
}

# ── External Secrets ─────────────────────────────────────────────────────────
#
# Materialises Secret Manager values into the Kubernetes Secret the chart reads
# through existingSecret. This is what keeps credentials out of BOTH the CI log
# and the Helm values: the pipeline never reads a secret, it only names one.
#
# Authentication is Workload Identity - the operator's ServiceAccount is
# annotated with a Google service account that holds secretAccessor on exactly
# the six fluidbox secrets and nothing else.

resource "kubernetes_namespace_v1" "external_secrets" {
  depends_on = [helm_release.cilium]

  metadata {
    name = "external-secrets"
    labels = {
      "app.kubernetes.io/managed-by" = "terraform"
    }
  }
}

resource "helm_release" "external_secrets" {
  name       = "external-secrets"
  repository = "https://charts.external-secrets.io"
  chart      = "external-secrets"
  version    = var.external_secrets_chart_version
  namespace  = kubernetes_namespace_v1.external_secrets.metadata[0].name

  # The CRDs must land before the chart's own ExternalSecret templates are
  # applied by a later helm run.
  set {
    name  = "installCRDs"
    value = "true"
  }

  set {
    name  = "serviceAccount.annotations.iam\\.gke\\.io/gcp-service-account"
    value = var.external_secrets_sa
  }

  # Keep the operator on the always-on system pool. On the sandbox pool it
  # would ride Spot capacity and disappear mid-preemption, which is a poor
  # place for the thing that refreshes credentials.
  set {
    name  = "nodeSelector.fluidbox\\.dev/role"
    value = "system"
  }

  set {
    name  = "webhook.nodeSelector.fluidbox\\.dev/role"
    value = "system"
  }

  set {
    name  = "certController.nodeSelector.fluidbox\\.dev/role"
    value = "system"
  }

  atomic          = true
  cleanup_on_fail = true
  wait            = true
  timeout         = 600
}

# ── Release namespace ────────────────────────────────────────────────────────
#
# Created here rather than by `helm --create-namespace` so the labels the
# NetworkPolicies select on are guaranteed present before the first install,
# not added as a side effect of one.

resource "kubernetes_namespace_v1" "fluidbox" {
  depends_on = [helm_release.cilium]

  metadata {
    name = var.namespace
    labels = {
      "app.kubernetes.io/name"       = "fluidbox"
      "app.kubernetes.io/managed-by" = "terraform"
      # Helm server-side-applies this label to the release namespace as its own
      # bookkeeping - it is not in the chart. Undeclared, it made every app-stack
      # plan a permanent one-line diff that Terraform removed and the next helm
      # upgrade restored. Declaring it ends the tug-of-war between two field
      # managers so a NON-empty plan here means real drift. Nothing selects on
      # it: every namespaceSelector uses kubernetes.io/metadata.name, which
      # Kubernetes maintains and no one can remove.
      "name" = var.namespace
      # Pod Security Admission. The control plane is an ordinary workload:
      # non-root, no privilege escalation, all capabilities dropped.
      "pod-security.kubernetes.io/enforce" = "restricted"
      "pod-security.kubernetes.io/audit"   = "restricted"
      "pod-security.kubernetes.io/warn"    = "restricted"
    }
  }
}
