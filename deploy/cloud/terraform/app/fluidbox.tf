# The UNCHANGED released chart, installed from the GHCR OCI registry at the
# release version. Everything M1-specific rides values (static file overlaid
# with the dynamic map below) — zero chart changes, per the M1 contract.

locals {
  server_extra_env = concat(
    [
      # Custody: envelope sealing under the platform KEK via Pod Identity.
      { name = "FLUIDBOX_KMS_MODE", value = "aws" },
      { name = "FLUIDBOX_KMS_AWS_KEY_ID", value = local.kms_kek_arn },
      # Per-tenant LiteLLM virtual keys (the fairness backstop; REQUIRED once
      # REQUIRE_SSO=1 — hosted+shared is a deliberate 503).
      { name = "FLUIDBOX_LLM_KEY_MODE", value = "tenant" },
      { name = "FLUIDBOX_LLM_TENANT_MODELS", value = var.llm_tenant_models },
      { name = "FLUIDBOX_LLM_TENANT_MAX_BUDGET", value = var.llm_tenant_max_budget },
      { name = "FLUIDBOX_LLM_TENANT_BUDGET_DURATION", value = var.llm_tenant_budget_duration },
      { name = "FLUIDBOX_DEFAULT_MODEL", value = var.default_model },
    ],
    var.require_sso ? [{ name = "FLUIDBOX_REQUIRE_SSO", value = "1" }] : [],
  )

  values_overlay = {
    server = merge(
      { extraEnv = local.server_extra_env },
      var.public_url != "" ? { publicUrl = var.public_url } : {},
    )
    ingress = {
      annotations = {
        "alb.ingress.kubernetes.io/security-groups" = local.alb_sg_id
      }
    }
  }
}

resource "helm_release" "fluidbox" {
  name       = "fluidbox"
  repository = "oci://ghcr.io/hrishikeshdkakkad/charts"
  chart      = "fluidbox"
  version    = var.chart_version
  namespace  = kubernetes_namespace_v1.fluidbox.metadata[0].name

  values = [
    file("${path.module}/../../values/eks-m1.yaml"),
    yamlencode(local.values_overlay),
  ]

  wait    = true
  timeout = var.helm_timeout_seconds

  depends_on = [
    kubernetes_deployment_v1.litellm,
    kubernetes_service_v1.litellm,
  ]
}

# The controller-created ALB's hostname (edge stack's origin; also the
# direct-ALB refusal check target).
data "kubernetes_ingress_v1" "fluidbox" {
  metadata {
    name      = "fluidbox-server"
    namespace = kubernetes_namespace_v1.fluidbox.metadata[0].name
  }

  depends_on = [helm_release.fluidbox]
}
