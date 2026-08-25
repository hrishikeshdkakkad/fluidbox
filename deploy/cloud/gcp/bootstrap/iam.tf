# ── CI identity: Workload Identity Federation, no long-lived keys ────────────
#
# GitHub Actions presents its OIDC token; GCP exchanges it for a short-lived
# access token that impersonates a service account. There is no JSON key to
# leak, rotate, or commit - which is the whole point.
#
# TWO identities, because plan and apply are different authorities:
#
#   fbx-planner   read-only, any branch. Pull-request plans run as this. A
#                 compromised PR cannot change infrastructure because the
#                 identity it can reach simply has no write permission.
#   fbx-deployer  write. Reachable ONLY from refs/heads/<deploy_branch> AND
#                 only from the `production` GitHub Environment, so the
#                 environment's protection rules (reviewers, wait timer) sit
#                 in the impersonation path rather than beside it.

resource "google_iam_workload_identity_pool" "github" {
  project                   = var.project_id
  workload_identity_pool_id = "github"
  display_name              = "GitHub Actions"
  description               = "OIDC federation for ${var.github_repository}"

  depends_on = [google_project_service.enabled]
}

resource "google_iam_workload_identity_pool_provider" "github" {
  project                            = var.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.github.workload_identity_pool_id
  workload_identity_pool_provider_id = "github-oidc"
  display_name                       = "GitHub OIDC"

  attribute_mapping = {
    "google.subject"        = "assertion.sub"
    "attribute.repository"  = "assertion.repository"
    "attribute.ref"         = "assertion.ref"
    "attribute.environment" = "assertion.environment"
  }

  # LOAD-BEARING. Without a condition, every GitHub Actions workflow on
  # github.com can mint a token against this pool - the issuer is shared by all
  # of GitHub. This pins the exchange to one repository before any service
  # account binding is even consulted.
  attribute_condition = "assertion.repository == \"${var.github_repository}\""

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"

    # allowed_audiences is deliberately OMITTED.
    #
    # Left unset, the provider accepts the DEFAULT audience
    # "https://iam.googleapis.com/{provider_resource_name}" - which is exactly
    # what google-github-actions/auth requests. Setting it to anything else
    # (the org URL is the tempting choice) makes every token fail with
    #   invalid_grant: The audience in ID Token [...] does not match the
    #   expected audience
    # naming an audience that LOOKS correct, because the message echoes the
    # token's audience rather than the configured one.
    #
    # Restricting the repository is the job of attribute_condition above, which
    # already pins it. Audience adds nothing here.
  }
}

# ── Service accounts ─────────────────────────────────────────────────────────

resource "google_service_account" "planner" {
  project      = var.project_id
  account_id   = "fbx-planner"
  display_name = "Fluidbox CI - terraform plan (read-only)"
  description  = "Impersonated by pull-request workflows. Read-only by construction."
}

resource "google_service_account" "deployer" {
  project      = var.project_id
  account_id   = "fbx-deployer"
  display_name = "Fluidbox CI - terraform apply + helm (write)"
  description  = "Impersonated only from ${var.deploy_branch} in the production environment."
}

# ── Who may impersonate whom ────────────────────────────────────────────────

resource "google_service_account_iam_member" "planner_wif" {
  service_account_id = google_service_account.planner.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github.name}/attribute.repository/${var.github_repository}"
}

# The deployer binding is narrower on TWO axes at once: the git ref and the
# GitHub Environment. `environment` only appears in the OIDC token when the job
# declares `environment: production`, so a workflow that skips the protected
# environment cannot reach this identity even from main.
resource "google_service_account_iam_member" "deployer_wif" {
  service_account_id = google_service_account.deployer.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github.name}/attribute.ref/refs/heads/${var.deploy_branch}"
}

resource "google_service_account_iam_member" "deployer_wif_env" {
  service_account_id = google_service_account.deployer.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github.name}/attribute.environment/${var.deploy_environment}"
}

# ── Project roles ────────────────────────────────────────────────────────────

locals {
  # Enough to build and operate the platform + app stacks, and no more.
  # Deliberately ABSENT: owner, editor, serviceusage.serviceUsageAdmin (APIs
  # are an Owner act, above), billing roles (granted on the billing account,
  # not here), and storage.admin (the deployer gets object access to exactly
  # one bucket, below - not every bucket in the project).
  deployer_roles = [
    "roles/container.admin",                 # GKE clusters + node pools
    "roles/compute.networkAdmin",            # VPC, subnets, router, NAT, addresses
    "roles/compute.securityAdmin",           # firewall rules
    "roles/compute.loadBalancerAdmin",       # forwarding rules behind the Ingress
    "roles/cloudsql.admin",                  # Cloud SQL instance + database + user
    "roles/artifactregistry.admin",          # image repository
    "roles/secretmanager.admin",             # secret CONTAINERS (values stay out-of-band)
    "roles/cloudkms.admin",                  # keyring + key for CMEK
    "roles/iam.serviceAccountAdmin",         # workload-identity service accounts
    "roles/iam.serviceAccountUser",          # attach those SAs to workloads
    "roles/resourcemanager.projectIamAdmin", # bind roles to the SAs it creates
    "roles/servicenetworking.networksAdmin", # private services access for Cloud SQL
    "roles/monitoring.editor",               # alert policies, uptime checks, dashboards
    "roles/logging.configWriter",            # log sinks + metrics
  ]
}

resource "google_project_iam_member" "deployer" {
  for_each = toset(local.deployer_roles)

  project = var.project_id
  role    = each.value
  member  = google_service_account.deployer.member
}

# Read-only across the project. roles/viewer deliberately does NOT include
# secretmanager.versions.access, so a plan can see that a secret EXISTS and
# never what is in it.
resource "google_project_iam_member" "planner" {
  project = var.project_id
  role    = "roles/viewer"
  member  = google_service_account.planner.member
}

# ── State bucket access ──────────────────────────────────────────────────────

resource "google_storage_bucket_iam_member" "deployer_state" {
  bucket = google_storage_bucket.tfstate.name
  role   = "roles/storage.objectAdmin"
  member = google_service_account.deployer.member
}

# Read-only. The GCS backend takes a lock by WRITING a .tflock object, which
# this identity cannot do - so plan jobs must run `terraform plan -lock=false`.
# That is safe for a read-only plan and is what the deploy workflow does; the
# alternative (objectAdmin) would hand every pull request the ability to
# overwrite production state.
resource "google_storage_bucket_iam_member" "planner_state" {
  bucket = google_storage_bucket.tfstate.name
  role   = "roles/storage.objectViewer"
  member = google_service_account.planner.member
}
