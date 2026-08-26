variable "project_id" {
  type    = string
  default = "fluidbox-506603"

  validation {
    condition     = var.project_id == "fluidbox-506603"
    error_message = "This repository deploys only to fluidbox-506603."
  }
}

variable "region" {
  type    = string
  default = "us-central1"
}

variable "zone" {
  type    = string
  default = "us-central1-c"
}

variable "cluster_name" {
  type    = string
  default = "fluidbox"
}

variable "namespace" {
  description = "Release namespace for the control plane."
  type        = string
  default     = "fluidbox"
}

variable "external_secrets_sa" {
  description = "Google service account email External Secrets impersonates (platform stack output external_secrets_service_account)."
  type        = string
}

variable "external_secrets_chart_version" {
  description = "Pinned. An operator that syncs every production credential is not a chart to float."
  type        = string
  default     = "0.12.1"
}

variable "cilium_mode" {
  description = <<-EOT
    Must match the platform stack. `upstream` installs self-managed Cilium here;
    `dataplane_v2` installs nothing (GKE manages it).

    Defaulting this to the mode the live deployment does NOT run is destructive
    in a quieter way than the platform stack: count would drop to 0 and Terraform
    would UNINSTALL the cluster's CNI. Keep it in lockstep with
    platform/variables.tf.
  EOT
  type        = string
  default     = "upstream"

  validation {
    condition     = contains(["dataplane_v2", "upstream"], var.cilium_mode)
    error_message = "cilium_mode must be dataplane_v2 or upstream."
  }
}

variable "pods_cidr" {
  description = "The cluster's Pod CIDR, passed to Cilium as ipv4NativeRoutingCIDR. Must match the platform stack's pods_cidr, or Cilium masquerades traffic it should route natively."
  type        = string
  default     = "10.20.0.0/14"
}

variable "cilium_chart_version" {
  description = "Pinned. A self-managed CNI is the last thing that should float."
  type        = string
  default     = "1.18.1"
}

variable "cilium_agent_not_ready_taint_key" {
  description = <<-EOT
    The startup taint every node is born with (platform stack output
    cilium_agent_not_ready_taint_key). Cilium's operator removes exactly this
    key once a node is prepared. Deliberately no default: it is fed from the
    platform output the way external_secrets_sa is, because a retyped value
    that drifts leaves every NEW node tainted NoExecute forever, with the netpol
    probe's "Unschedulable" as the only symptom.
  EOT
  type        = string
}
