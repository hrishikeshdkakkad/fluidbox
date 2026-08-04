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
    namespace = local.namespace
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
        # The codex harness catalog (harness.rs): explicit default + wildcard,
        # mirroring the anthropic shape. Routing alone does not grant access —
        # minted tenant keys still carry the llm_tenant_models allowlist.
        - model_name: gpt-5.4-mini
          litellm_params:
            model: openai/gpt-5.4-mini
            api_key: os.environ/OPENAI_API_KEY
        - model_name: "gpt-*"
          litellm_params:
            model: "openai/gpt-*"
            api_key: os.environ/OPENAI_API_KEY
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
    namespace = local.namespace
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
            name = "OPENAI_API_KEY"
            value_from {
              secret_key_ref {
                name = "fluidbox-secrets"
                key  = "OPENAI_API_KEY"
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
              memory = var.litellm_memory_request
            }
            # The 2Gi figure came from the chart's BUNDLED LiteLLM (2026-07-17,
            # re-confirmed 2026-07-22). The DB-BACKED image M1 needs is a
            # different animal: it runs prisma at startup and was OOMKilled
            # (exit 137) at 2Gi twenty-five seconds into boot — on a node that
            # was only 22% committed, so this is the CGROUP limit, not node
            # pressure. Do not "fix" a recurrence by shrinking it.
            limits = {
              cpu    = "1"
              memory = var.litellm_memory_limit
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
    namespace = local.namespace
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
