# ── VPC ──────────────────────────────────────────────────────────────────────
#
# Custom mode: auto mode would create a subnet in every region with ranges we
# do not control, and one of them would eventually collide with the Private
# Service Access range Cloud SQL needs.

resource "google_compute_network" "vpc" {
  project                         = var.project_id
  name                            = "fluidbox"
  auto_create_subnetworks         = false
  routing_mode                    = "REGIONAL"
  delete_default_routes_on_create = false
  description                     = "Fluidbox control plane + sandbox data plane"
}

resource "google_compute_subnetwork" "gke" {
  project       = var.project_id
  name          = "fluidbox-gke"
  region        = var.region
  network       = google_compute_network.vpc.id
  ip_cidr_range = var.subnet_cidr

  # Nodes have no external addresses (see gke.tf enable_private_nodes); Private
  # Google Access is what still lets them reach Artifact Registry, Cloud
  # Logging and the other *.googleapis.com endpoints without traversing NAT.
  private_ip_google_access = true

  secondary_ip_range {
    range_name    = "pods"
    ip_cidr_range = var.pods_cidr
  }

  secondary_ip_range {
    range_name    = "services"
    ip_cidr_range = var.services_cidr
  }

  log_config {
    aggregation_interval = "INTERVAL_10_MIN"
    flow_sampling        = 0.1
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

# ── Egress: Cloud Router + NAT ───────────────────────────────────────────────
#
# Private nodes still need the public internet: GHCR for the runner images,
# api.anthropic.com through LiteLLM, the org's OIDC issuer, GitHub. NAT gives
# them that through ONE stable set of addresses, which is also what makes an
# upstream allowlist possible later.
#
# This does NOT weaken sandbox containment. Sandbox egress is decided by
# NetworkPolicy (zeroEgress) inside the cluster, long before a packet could
# reach NAT.

resource "google_compute_router" "nat" {
  project = var.project_id
  name    = "fluidbox-nat-router"
  region  = var.region
  network = google_compute_network.vpc.id
}

resource "google_compute_address" "nat" {
  project      = var.project_id
  name         = "fluidbox-nat"
  region       = var.region
  address_type = "EXTERNAL"
  description  = "Stable egress address for the cluster. Give this to upstreams that allowlist by IP."
}

resource "google_compute_router_nat" "nat" {
  project = var.project_id
  name    = "fluidbox-nat"
  router  = google_compute_router.nat.name
  region  = var.region

  nat_ip_allocate_option = "MANUAL_ONLY"
  nat_ips                = [google_compute_address.nat.self_link]

  source_subnetwork_ip_ranges_to_nat = "LIST_OF_SUBNETWORKS"

  subnetwork {
    name = google_compute_subnetwork.gke.id
    source_ip_ranges_to_nat = [
      "PRIMARY_IP_RANGE",
      "LIST_OF_SECONDARY_IP_RANGES",
    ]
    secondary_ip_range_names = ["pods"]
  }

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}

# ── Private Service Access (Cloud SQL private IP) ────────────────────────────
#
# Cloud SQL with no public address lives on a Google-managed network peered to
# ours. That peering consumes a range from OUR space, reserved here.

resource "google_compute_global_address" "sql_peering" {
  project       = var.project_id
  name          = "fluidbox-sql-peering"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  address       = split("/", var.sql_peering_cidr)[0]
  prefix_length = tonumber(split("/", var.sql_peering_cidr)[1])
  network       = google_compute_network.vpc.id
}

resource "google_service_networking_connection" "sql" {
  network                 = google_compute_network.vpc.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.sql_peering.name]

  # Without this, `terraform destroy` leaves the peering behind and the next
  # apply fails on a range that is already consumed by an invisible connection.
  deletion_policy = "ABANDON"
}

# ── Firewall ─────────────────────────────────────────────────────────────────
#
# GKE programs the rules its own data plane needs. These are the two it does
# not: load-balancer health probes, and a default-deny floor for ingress that
# nothing has explicitly allowed.

resource "google_compute_firewall" "health_checks" {
  project     = var.project_id
  name        = "fluidbox-allow-health-checks"
  network     = google_compute_network.vpc.name
  description = "Google Front End health-check probers. These are fixed, documented Google ranges - not arbitrary internet."
  direction   = "INGRESS"
  priority    = 900

  # https://cloud.google.com/load-balancing/docs/health-check-concepts
  source_ranges = ["130.211.0.0/22", "35.191.0.0/16"]
  target_tags   = ["fluidbox-node"]

  allow {
    protocol = "tcp"
    ports    = ["8787", "10256", "30000-32767"]
  }
}

resource "google_compute_firewall" "deny_ingress_default" {
  project     = var.project_id
  name        = "fluidbox-deny-ingress-default"
  network     = google_compute_network.vpc.name
  description = "Default-deny floor. Lower priority than every allow above and than GKE's own rules, so it only catches what nothing else permitted."
  direction   = "INGRESS"
  priority    = 65000

  source_ranges = ["0.0.0.0/0"]

  deny {
    protocol = "all"
  }

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

# ── Ingress address ──────────────────────────────────────────────────────────
#
# Reserved here, not by the Ingress controller, for one reason: a
# controller-allocated address changes if the Ingress is ever recreated, and
# the DNS record for it lives in a DIFFERENT cloud (Route 53). A static
# address makes that record durable.

resource "google_compute_global_address" "ingress" {
  project      = var.project_id
  name         = "fluidbox-ingress"
  address_type = "EXTERNAL"
  ip_version   = "IPV4"
  description  = "GCLB frontend for ${var.control_plane_host}. Referenced by the chart's kubernetes.io/ingress.global-static-ip-name annotation."
}
