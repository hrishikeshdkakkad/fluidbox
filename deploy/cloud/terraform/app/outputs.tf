output "alb_hostname" {
  description = <<-EOT
    The Ingress-created ALB hostname — INFORMATIONAL ONLY, and normally EMPTY
    on the first apply: `helm --wait` waits for pods, not for the ALB
    controller to write status.loadBalancer, so the data source usually reads
    before the hostname exists. A later refresh/apply populates it. Nothing
    depends on this being non-empty — the edge stack rediscovers the ALB
    itself via `data "aws_lb"` on the controller's tags.
  EOT
  value       = try(data.kubernetes_ingress_v1.fluidbox.status[0].load_balancer[0].ingress[0].hostname, "")
}

output "namespace" {
  value = kubernetes_namespace_v1.fluidbox.metadata[0].name
}

output "litellm_upstream" {
  value = "http://litellm.fluidbox.svc.cluster.local:4000"
}
