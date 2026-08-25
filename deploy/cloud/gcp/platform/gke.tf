# ── GKE cluster ──────────────────────────────────────────────────────────────
#
# Standard (not Autopilot), zonal, Dataplane V2.
#
# Standard because the sandbox plane needs node-level control Autopilot does
# not give: a Spot pool that scales to zero, taints that keep agent workloads
# off the control-plane node, and - if hard isolation is ever turned on - a
# gVisor RuntimeClass. Autopilot also prices per pod request, which is the
# wrong shape for a fleet that is mostly idle.
#
# Dataplane V2 because NetworkPolicy enforcement is not optional here. The
# server refuses to start runs until a boot probe proves the CNI actually drops
# traffic (netpol.requireEnforced), and DPv2 is Cilium - enforcing natively,
# with no add-on to forget.

resource "google_container_cluster" "fluidbox" {
  provider = google-beta

  project  = var.project_id
  name     = "fluidbox"
  location = var.zone

  # The default pool exists only to create the cluster; the real pools are
  # declared separately so their settings can change without recreating it.
  remove_default_node_pool = true
  initial_node_count       = 1

  network    = google_compute_network.vpc.id
  subnetwork = google_compute_subnetwork.gke.id

  networking_mode = "VPC_NATIVE"

  # IMMUTABLE. Changing this REPLACES the cluster - see var.cilium_mode.
  #   dataplane_v2 -> GKE's managed Cilium (ADVANCED_DATAPATH)
  #   upstream     -> legacy datapath, so self-managed Cilium owns the CNI
  datapath_provider = var.cilium_mode == "dataplane_v2" ? "ADVANCED_DATAPATH" : "LEGACY_DATAPATH"

  # Dataplane-V2-only knob: it exposes the CiliumClusterwideNetworkPolicy CRD.
  # Meaningless (and rejected) on the legacy datapath, where upstream Cilium
  # brings its own CRDs - both of them.
  enable_cilium_clusterwide_network_policy = (
    var.cilium_mode == "dataplane_v2" ? var.enable_cilium_clusterwide_network_policy : null
  )

  # A cluster is not a cattle resource: deleting it destroys every PVC and
  # every running sandbox. Removal is a reviewed act - see the variable.
  deletion_protection = var.cluster_deletion_protection

  release_channel {
    channel = var.gke_release_channel
  }

  ip_allocation_policy {
    cluster_secondary_range_name  = "pods"
    services_secondary_range_name = "services"
  }

  private_cluster_config {
    enable_private_nodes = true
    # Public control-plane endpoint. See var.master_authorized_cidrs for the
    # residual this accepts and why CI needs it.
    enable_private_endpoint = false
    master_ipv4_cidr_block  = "172.16.0.0/28"
  }

  dynamic "master_authorized_networks_config" {
    for_each = length(var.master_authorized_cidrs) > 0 ? [1] : []
    content {
      dynamic "cidr_blocks" {
        for_each = var.master_authorized_cidrs
        content {
          cidr_block   = cidr_blocks.value.cidr_block
          display_name = cidr_blocks.value.display_name
        }
      }
    }
  }

  # Pods authenticate to Google APIs as a Kubernetes ServiceAccount mapped to a
  # Google service account - no node-wide credential, no key file.
  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }

  addons_config {
    http_load_balancing {
      disabled = false # the GKE Ingress controller
    }
    horizontal_pod_autoscaling {
      disabled = false
    }
    gce_persistent_disk_csi_driver_config {
      enabled = true # standard-rwo for the archive PVC
    }
    # Dataplane V2 supplies NetworkPolicy. The Calico add-on is the ALTERNATIVE
    # implementation and enabling both is rejected by the API.
    network_policy_config {
      disabled = true
    }
  }

  logging_config {
    enable_components = ["SYSTEM_COMPONENTS", "WORKLOADS"]
  }

  monitoring_config {
    enable_components = ["SYSTEM_COMPONENTS"]
    managed_prometheus {
      enabled = true
    }
  }

  # Per-namespace cost attribution, which is what makes "what did the sandbox
  # plane cost this month" answerable at all.
  cost_management_config {
    enabled = true
  }

  maintenance_policy {
    recurring_window {
      # Sunday 08:00-16:00 UTC = the quietest window for a US-hours workload.
      start_time = "2026-01-04T08:00:00Z"
      end_time   = "2026-01-04T16:00:00Z"
      recurrence = "FREQ=WEEKLY;BYDAY=SU"
    }
  }

  # etcd application-layer encryption for Secret objects, using our own key.
  # Without it, Kubernetes Secrets are encrypted only by Google's default
  # envelope - which is fine, but not a key we can revoke.
  database_encryption {
    state    = "ENCRYPTED"
    key_name = google_kms_crypto_key.gke_etcd.id
  }

  resource_labels = var.labels

  depends_on = [
    google_service_networking_connection.sql,
    google_kms_crypto_key_iam_member.gke_etcd,
  ]

  lifecycle {
    ignore_changes = [
      # The release channel moves the master version on its own schedule;
      # Terraform must not fight it every plan.
      min_master_version,
      node_version,
      # PROVIDER BUG, not drift. The provider validates this attribute against
      # ["ENCRYPTED", "DECRYPTED"] but the API READS BACK
      # "ALL_OBJECTS_ENCRYPTION_ENABLED", so the two never agree and every plan
      # reports "1 to change" forever. That matters more than it sounds in a
      # commit-to-production pipeline: a plan that always shows a change is a
      # plan nobody reads, which is exactly how a real change slips through.
      #
      # Only `state` is ignored - `key_name` above stays tracked, so pointing
      # the cluster at a DIFFERENT KMS key is still caught.
      database_encryption[0].state,
    ]
  }
}

# ── System pool: always on ───────────────────────────────────────────────────

resource "google_container_node_pool" "system" {
  provider = google-beta

  project  = var.project_id
  name     = "system"
  location = var.zone
  cluster  = google_container_cluster.fluidbox.name

  node_count = null

  autoscaling {
    min_node_count = var.system_min_nodes
    max_node_count = var.system_max_nodes
  }

  management {
    auto_repair  = true
    auto_upgrade = true
  }

  # THE lean-tier HA fix. max_surge=1 / max_unavailable=0 makes an upgrade ADD
  # a node, drain onto it, then remove the old one - so a single-node pool
  # still upgrades without dropping the control plane. The extra node is billed
  # only for the minutes the upgrade runs, which is why this costs almost
  # nothing while removing the "single node = guaranteed downtime" caveat.
  upgrade_settings {
    max_surge       = 1
    max_unavailable = 0
    strategy        = "SURGE"
  }

  node_config {
    machine_type = var.system_machine_type
    disk_size_gb = 100
    disk_type    = "pd-balanced"
    image_type   = "COS_CONTAINERD"

    # Least privilege at the NODE level. Pods get their own identity through
    # Workload Identity; this account only needs to write logs/metrics and pull
    # images.
    service_account = google_service_account.node.email
    oauth_scopes    = ["https://www.googleapis.com/auth/cloud-platform"]

    workload_metadata_config {
      # Blocks the legacy metadata endpoints from pods entirely - the same
      # 169.254.169.254 class the control plane's own egress predicate refuses.
      mode = "GKE_METADATA"
    }

    shielded_instance_config {
      enable_secure_boot          = true
      enable_integrity_monitoring = true
    }

    # Streams image layers on demand instead of pulling the whole image before
    # start. The runner images are ~1.5 GB, so this is the difference between a
    # sandbox starting in seconds and starting in minutes.
    gcfs_config {
      enabled = true
    }

    labels = merge(var.labels, {
      "fluidbox.dev/role" = "system"
    })

    # Self-managed Cilium only. Holds every pod off a node until Cilium has
    # prepared it and removed the taint. Without it, pods start on whatever CNI
    # is present at boot and stay UNMANAGED - and because a GKE node upgrade or
    # reboot re-applies the stock CNI config, this is not just a first-boot
    # concern. It is the mechanism that makes a self-managed CNI survivable here.
    dynamic "taint" {
      for_each = var.cilium_mode == "upstream" ? [1] : []
      content {
        key    = "node.cilium.io/agent-not-ready"
        value  = "true"
        effect = "NO_EXECUTE"
      }
    }

    tags = ["fluidbox-node", "fluidbox-system"]

    metadata = {
      disable-legacy-endpoints = "true"
    }
  }

  lifecycle {
    ignore_changes = [node_config[0].kubelet_config, version]
  }
}

# ── Sandbox pool: spot, scale-to-zero ────────────────────────────────────────
#
# Tainted so nothing schedules here unless it explicitly tolerates the taint.
# The chart puts that toleration on sandbox pods only, which keeps the control
# plane off preemptible capacity.

resource "google_container_node_pool" "sandbox" {
  provider = google-beta

  project  = var.project_id
  name     = "sandbox"
  location = var.zone
  cluster  = google_container_cluster.fluidbox.name

  node_count = null

  autoscaling {
    min_node_count = var.sandbox_min_nodes
    max_node_count = var.sandbox_max_nodes
  }

  management {
    auto_repair  = true
    auto_upgrade = true
  }

  upgrade_settings {
    max_surge       = 1
    max_unavailable = 0
    strategy        = "SURGE"
  }

  node_config {
    machine_type = var.sandbox_machine_type
    disk_size_gb = 100
    disk_type    = "pd-balanced"
    image_type   = "COS_CONTAINERD"
    spot         = var.sandbox_spot

    service_account = google_service_account.node.email
    oauth_scopes    = ["https://www.googleapis.com/auth/cloud-platform"]

    workload_metadata_config {
      mode = "GKE_METADATA"
    }

    shielded_instance_config {
      enable_secure_boot          = true
      enable_integrity_monitoring = true
    }

    gcfs_config {
      enabled = true
    }

    labels = merge(var.labels, {
      "fluidbox.dev/role" = "sandbox"
    })

    taint {
      key    = "fluidbox.dev/role"
      value  = "sandbox"
      effect = "NO_SCHEDULE"
    }

    dynamic "taint" {
      for_each = var.cilium_mode == "upstream" ? [1] : []
      content {
        key    = "node.cilium.io/agent-not-ready"
        value  = "true"
        effect = "NO_EXECUTE"
      }
    }

    tags = ["fluidbox-node", "fluidbox-sandbox"]

    metadata = {
      disable-legacy-endpoints = "true"
    }
  }

  lifecycle {
    ignore_changes = [node_config[0].kubelet_config, version]
  }
}
