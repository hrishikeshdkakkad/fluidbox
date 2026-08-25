# Cluster-level prerequisites that must exist BEFORE the fluidbox chart is
# installed, and that are not part of the application itself.
#
# Deliberately small. The fluidbox release is NOT managed here: it is installed
# by `helm upgrade --install` from the deploy pipeline, so that `helm history`
# and `helm rollback` remain the operator's interface. Wrapping it in Terraform
# would replace a one-command, revision-numbered rollback with a state-file
# edit, which is the wrong tool for the job the goal actually asks for.

terraform {
  required_version = ">= 1.9.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.12"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.35"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.17"
    }
  }

  backend "gcs" {}
}


# user_project_override + billing_project: some APIs (billingbudgets in
# particular) refuse a user-ADC caller that carries no quota project, with a
# confusing "SERVICE_DISABLED" naming Google's own client project rather than
# ours. These two send X-Goog-User-Project on every request, which is the
# reproducible fix - `gcloud auth application-default set-quota-project` fixes
# only the machine it is run on, and CI would hit the same wall.
provider "google" {
  project               = var.project_id
  region                = var.region
  user_project_override = true
  billing_project       = var.project_id
}

data "google_client_config" "this" {}

data "google_container_cluster" "fluidbox" {
  project  = var.project_id
  name     = var.cluster_name
  location = var.zone
}

locals {
  host       = "https://${data.google_container_cluster.fluidbox.endpoint}"
  cluster_ca = base64decode(data.google_container_cluster.fluidbox.master_auth[0].cluster_ca_certificate)
}

provider "kubernetes" {
  host                   = local.host
  token                  = data.google_client_config.this.access_token
  cluster_ca_certificate = local.cluster_ca
}

provider "helm" {
  kubernetes {
    host                   = local.host
    token                  = data.google_client_config.this.access_token
    cluster_ca_certificate = local.cluster_ca
  }
}
