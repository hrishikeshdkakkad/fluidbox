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
  metadata {
    name = var.namespace
    labels = {
      "app.kubernetes.io/name"       = "fluidbox"
      "app.kubernetes.io/managed-by" = "terraform"
      # Pod Security Admission. The control plane is an ordinary workload:
      # non-root, no privilege escalation, all capabilities dropped.
      "pod-security.kubernetes.io/enforce" = "restricted"
      "pod-security.kubernetes.io/audit"   = "restricted"
      "pod-security.kubernetes.io/warn"    = "restricted"
    }
  }
}
