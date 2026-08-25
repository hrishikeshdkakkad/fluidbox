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
