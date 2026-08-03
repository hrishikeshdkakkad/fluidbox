output "alb_hostname" {
  description = "The Ingress-created ALB (edge stack origin; direct requests to it must be refused once the origin header rule is live)."
  value       = try(data.kubernetes_ingress_v1.fluidbox.status[0].load_balancer[0].ingress[0].hostname, "")
}

output "namespace" {
  value = kubernetes_namespace_v1.fluidbox.metadata[0].name
}

output "litellm_upstream" {
  value = "http://litellm.fluidbox.svc.cluster.local:4000"
}
