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
  description = "Must match the platform stack. `upstream` installs self-managed Cilium here; `dataplane_v2` installs nothing (GKE manages it)."
  type        = string
  default     = "dataplane_v2"

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
