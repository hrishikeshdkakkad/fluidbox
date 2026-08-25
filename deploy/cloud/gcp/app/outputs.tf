output "namespace" {
  value = kubernetes_namespace_v1.fluidbox.metadata[0].name
}

output "external_secrets_version" {
  value = helm_release.external_secrets.version
}

output "priority_classes" {
  value = {
    control_plane = kubernetes_priority_class_v1.control_plane.metadata[0].name
    sandbox       = kubernetes_priority_class_v1.sandbox.metadata[0].name
  }
}
