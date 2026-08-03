# External LiteLLM — COMPOSITION, not a chart change. The bundled chart
# LiteLLM stays disabled ("External LiteLLM is the production default" —
# values.yaml), because tenant virtual keys (FLUIDBOX_LLM_KEY_MODE=tenant)
# require LiteLLM backed by its OWN Postgres, which the bundled template
# deliberately does not wire. This Deployment mirrors the bundled template's
# hardening and config, adds DATABASE_URL from the out-of-band Secret
# `fluidbox-litellm-db` (key DATABASE_URL — a small dedicated Neon database,
# NEVER the fluidbox app DB), and stays ClusterIP-only + unreachable from
# sandboxes (their egress NetworkPolicy allows only the control plane :8788).

resource "kubernetes_config_map_v1" "litellm" {
  metadata {
    name      = "litellm"
    namespace = kubernetes_namespace_v1.fluidbox.metadata[0].name
  }

  data = {
    "config.yaml" = <<-EOT
      model_list:
        - model_name: claude-haiku-4-5
          litellm_params:
            model: anthropic/claude-haiku-4-5-20251001
            api_key: os.environ/ANTHROPIC_API_KEY
        - model_name: "claude-*"
          litellm_params:
            model: "anthropic/claude-*"
            api_key: os.environ/ANTHROPIC_API_KEY
      general_settings:
        master_key: os.environ/LITELLM_MASTER_KEY
      litellm_settings:
        drop_params: true
    EOT
  }
}

resource "kubernetes_deployment_v1" "litellm" {
  metadata {
    name      = "litellm"
    namespace = kubernetes_namespace_v1.fluidbox.metadata[0].name
    labels    = { app = "litellm" }
  }

  spec {
    replicas = 1
    selector {
      match_labels = { app = "litellm" }
    }

    template {
      metadata {
        labels = { app = "litellm" }
        annotations = {
          "checksum/config" = sha256(kubernetes_config_map_v1.litellm.data["config.yaml"])
        }
      }

      spec {
        security_context {
          run_as_non_root = true
          run_as_user     = 1000
          run_as_group    = 1000
          fs_group        = 1000
          seccomp_profile {
            type = "RuntimeDefault"
          }
        }

        container {
          name  = "litellm"
          image = var.litellm_image
          args  = ["--config", "/etc/litellm/config.yaml", "--port", "4000", "--num_workers", "1"]

          port {
            name           = "http"
            container_port = 4000
          }

          env {
            name = "LITELLM_MASTER_KEY"
            value_from {
              secret_key_ref {
                name = "fluidbox-secrets"
                key  = "LITELLM_MASTER_KEY"
              }
            }
          }
          env {
            name = "ANTHROPIC_API_KEY"
            value_from {
              secret_key_ref {
                name = "fluidbox-secrets"
                key  = "ANTHROPIC_API_KEY"
              }
            }
          }
          env {
            name = "DATABASE_URL"
            value_from {
              secret_key_ref {
                name = "fluidbox-litellm-db"
                key  = "DATABASE_URL"
              }
            }
          }

          volume_mount {
            name       = "config"
            mount_path = "/etc/litellm"
          }

          resources {
            requests = {
              cpu    = "250m"
              memory = "512Mi"
            }
            # The proven 2Gi (the chart's 1Gi default OOMKilled on EKS —
            # 2026-07-17 finding, re-confirmed 2026-07-22).
            limits = {
              cpu    = "1"
              memory = "2Gi"
            }
          }

          readiness_probe {
            http_get {
              path = "/health/readiness"
              port = 4000
            }
            initial_delay_seconds = 20
            period_seconds        = 15
            timeout_seconds       = 5
          }
        }

        volume {
          name = "config"
          config_map {
            name = kubernetes_config_map_v1.litellm.metadata[0].name
          }
        }
      }
    }
  }

  wait_for_rollout = true
}

resource "kubernetes_service_v1" "litellm" {
  metadata {
    name      = "litellm"
    namespace = kubernetes_namespace_v1.fluidbox.metadata[0].name
    labels    = { app = "litellm" }
  }

  spec {
    type     = "ClusterIP"
    selector = { app = "litellm" }
    port {
      name        = "http"
      port        = 4000
      target_port = "http"
    }
  }
}
