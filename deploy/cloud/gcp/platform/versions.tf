terraform {
  required_version = ">= 1.9.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.12"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "~> 6.12"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  # Remote state in the bootstrap bucket. Bucket + prefix are supplied at init:
  #   terraform init \
  #     -backend-config="bucket=fluidbox-506603-tfstate" \
  #     -backend-config="prefix=platform"
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

provider "google-beta" {
  project               = var.project_id
  region                = var.region
  user_project_override = true
  billing_project       = var.project_id
}
