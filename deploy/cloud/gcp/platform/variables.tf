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
  description = "Zone for the ZONAL GKE cluster and the Cloud SQL primary. Zonal is deliberate on the lean tier: GKE's free tier credit ($74.40/mo) cancels exactly one cluster's management fee, and a regional control plane costs the same fee three times over for a deployment whose data plane is a single node anyway. The trade-off is explicit: a zone outage takes the control plane down. See docs/hosted/gcp-architecture.md."
  type        = string
  default     = "us-central1-c"
}

# ── Network ──────────────────────────────────────────────────────────────────

variable "subnet_cidr" {
  description = "Primary range: node addresses."
  type        = string
  default     = "10.10.0.0/20"
}

variable "pods_cidr" {
  description = "Secondary range for Pod IPs. GKE allocates a /24 per node out of this, so it must be far larger than the node count suggests."
  type        = string
  default     = "10.20.0.0/14"
}

variable "services_cidr" {
  description = "Secondary range for ClusterIPs. The chart's networkGrants.dnsClusterIP must be a free address INSIDE this range."
  type        = string
  default     = "10.24.0.0/20"
}

variable "sql_peering_cidr" {
  description = "Range reserved for Private Service Access (the peered network Cloud SQL lives on). Must not overlap anything above."
  type        = string
  default     = "10.30.0.0/16"
}

variable "master_authorized_cidrs" {
  description = <<-EOT
    CIDRs allowed to reach the GKE control-plane endpoint, as [{cidr_block, display_name}].

    EMPTY (the default) leaves the endpoint reachable from any address, protected
    by IAM and TLS client certs only - which is what lets GitHub Actions, whose
    egress addresses are large and change without notice, run helm against the
    cluster with no bastion. That is a real, named residual: it exposes the API
    server to network-level attack and to credential-stuffing attempts, and the
    only thing standing in front of it is Google's IAM.

    Set it (operator office IP + a NAT egress IP for CI) whenever you have a
    stable egress address. The stronger fix is Connect Gateway, which removes
    the public endpoint entirely; it is a documented follow-up, not wired here.
  EOT
  type = list(object({
    cidr_block   = string
    display_name = string
  }))
  default = []
}

# ── Cluster capacity (LEAN tier - see docs/hosted/gcp-architecture.md) ───────

variable "system_machine_type" {
  description = "Machine type for the always-on pool that runs the control plane, LiteLLM and GKE system pods."
  type        = string
  default     = "e2-standard-4"
}

variable "system_min_nodes" {
  description = "Always-on floor. 1 on the lean tier. Upgrades stay near-zero-downtime anyway because the pool surges (max_surge=1, max_unavailable=0) rather than draining in place."
  type        = number
  default     = 1
}

variable "system_max_nodes" {
  description = "Ceiling for the autoscaler AND the headroom a surge upgrade uses."
  type        = number
  default     = 3
}

variable "sandbox_machine_type" {
  description = "Machine type for agent sandboxes."
  type        = string
  default     = "e2-standard-4"
}

variable "sandbox_min_nodes" {
  description = "Zero. The sandbox pool costs nothing while idle, which is what makes always-on affordable."
  type        = number
  default     = 0
}

variable "sandbox_max_nodes" {
  type    = number
  default = 3
}

variable "sandbox_spot" {
  description = "Run sandboxes on Spot VMs (60-91 percent cheaper, preemptible with 30s notice). Safe here: a preempted sandbox is a failed run the control plane already knows how to re-drive, and no control-plane state lives on these nodes."
  type        = bool
  default     = true
}

variable "gke_release_channel" {
  type    = string
  default = "REGULAR"

  validation {
    condition     = contains(["RAPID", "REGULAR", "STABLE"], var.gke_release_channel)
    error_message = "gke_release_channel must be RAPID, REGULAR or STABLE."
  }
}

# ── Database ─────────────────────────────────────────────────────────────────

variable "sql_tier" {
  description = "Cloud SQL machine tier. db-g1-small is the lean choice (1 shared vCPU / 1.7 GiB)."
  type        = string
  default     = "db-g1-small"
}

variable "sql_disk_size_gb" {
  type    = number
  default = 20
}

variable "sql_max_connections" {
  description = <<-EOT
    Postgres max_connections, set explicitly rather than left to the tier default.

    This is load-bearing on a small tier. The control plane holds
    `replicas x (FLUIDBOX_DB_MAX_CONNECTIONS + 2)` - the +2 being the two
    LISTEN/NOTIFY connections each replica keeps outside the pool - and a
    db-g1-small defaults to roughly 50, which leaves almost no headroom for
    migrations, psql, or a rolling upgrade running two generations at once.
  EOT
  type        = number
  default     = 100
}

variable "sql_availability_type" {
  description = "ZONAL (lean) or REGIONAL (automatic failover, roughly double the cost)."
  type        = string
  default     = "ZONAL"

  validation {
    condition     = contains(["ZONAL", "REGIONAL"], var.sql_availability_type)
    error_message = "sql_availability_type must be ZONAL or REGIONAL."
  }
}

variable "sql_backup_retention_days" {
  type    = number
  default = 7
}

# ── Edge ─────────────────────────────────────────────────────────────────────

variable "cilium_mode" {
  description = <<-EOT
    Which Cilium the cluster runs, and therefore which network policies are
    expressible.

      dataplane_v2   GKE's managed Cilium. Google patches it, nothing to
                     operate - but it exposes only CiliumClusterwideNetworkPolicy
                     (behind enable_cilium_clusterwide_network_policy) and NO
                     namespaced CiliumNetworkPolicy. Fluidbox's per-run enforcer
                     writes the namespaced kind, so governed egress is
                     IMPOSSIBLE and every sandbox is offline-only.

      upstream       Legacy datapath plus self-managed upstream Cilium (installed
                     by the app stack). Provides BOTH policy CRDs, so governed
                     egress works. Verified on a probe cluster before adoption:
                     a namespaced CNP carrying toFQDNs was accepted Valid=True.

    CHANGING THIS REPLACES THE CLUSTER. datapath_provider is immutable, so
    Terraform destroys and recreates - every workload, PVC and Ingress with it.

    The cost of `upstream` is ongoing, not one-off: GKE stops managing the CNI,
    and node upgrades or reboots can undo Cilium's node configuration. The
    agent-not-ready taint below is what makes that survivable - pods are held off
    a node until Cilium has re-prepared it.
  EOT
  type        = string
  default     = "dataplane_v2"

  validation {
    condition     = contains(["dataplane_v2", "upstream"], var.cilium_mode)
    error_message = "cilium_mode must be dataplane_v2 or upstream."
  }
}

variable "enable_cilium_clusterwide_network_policy" {
  description = <<-EOT
    Expose the CiliumClusterwideNetworkPolicy CRD on GKE Dataplane V2, which is
    what the chart's governed sandbox egress (networkGrants) renders.

    NOT ON BY DEFAULT IN GKE, and the failure mode is misleading: the CRD is
    simply absent, so `kubectl get crd | grep cilium` shows Cilium's STATE CRDs
    (endpoints, identities, nodes) and none of its POLICY CRDs - which reads as
    "Google withholds Cilium policy on DPv2" rather than "this is an opt-in
    flag". It is an opt-in flag, available since GKE 1.28.6-gke.1095000 /
    1.29.1-gke.1016000, and it applies IN PLACE to an existing cluster.

    NECESSARY BUT NOT SUFFICIENT for fluidbox's governed egress. This flag
    grants the CLUSTERWIDE CRD only. Fluidbox's PER-RUN enforcer writes
    NAMESPACED `CiliumNetworkPolicy` objects
    (crates/fluidbox-provider-k8s/src/enforcer.rs, `cnp_resource()`), and GKE
    ships no namespaced variant and offers no flag for one - so
    FLUIDBOX_NETWORK_ENFORCER=cilium still refuses to boot with "this cluster
    does not serve cilium.io/v2".

    Left ON: it is harmless, it matches the live cluster, the chart's deny-wall
    baseline CCNP does apply through it, and it is the prerequisite for any
    future move to clusterwide-only per-run policies. It does NOT make
    networkGrants usable on GKE today - see docs/hosted/gcp-architecture.md.
  EOT
  type        = bool
  default     = true
}

variable "enable_gcs_archive_store" {
  description = <<-EOT
    Provision the GCS bucket + HMAC key for the chart's archiveStore "s3"
    backend. DEFAULT OFF, and the default is not caution - it is a policy
    constraint.

    That backend needs a STATIC HMAC key: the chart supports neither workload
    identity nor STS for it, because the point of the backend is that MinIO and
    R2 behave identically. Creating one is refused by the org policy
    `constraints/iam.disableServiceAccountKeyCreation`, which is ENFORCED on
    this project (inherited - Google's secure-by-default for projects with no
    organization). That policy exists precisely to stop long-lived static
    credentials, so the right response is to do without one, not to seek an
    exception.

    With this off the control plane uses the node-local archive PVC, which
    needs no credential at all. The cost is real and is documented in
    docs/hosted/gcp-architecture.md: one ReadWriteOnce volume means ONE server
    replica, which means `strategy: Recreate` (a brief outage on every upgrade)
    and no meaningful PodDisruptionBudget or HPA.

    Turn this on ONLY if the constraint is deliberately lifted for this project.
  EOT
  type        = bool
  default     = false
}

variable "control_plane_host" {
  description = "Public hostname for the GKE control-plane origin. The dashboard on platform.fluidzero.ai rewrites /v1/* here, so this needs its own certificate and its own DNS record."
  type        = string
  default     = "api.platform.fluidzero.ai"
}

variable "dashboard_host" {
  description = "Browser-facing origin (Vercel). Feeds FLUIDBOX_PUBLIC_URL, the OAuth redirect_uri and the cookie Origin check - it is NOT served from this project."
  type        = string
  default     = "platform.fluidzero.ai"
}

# ── Operations ───────────────────────────────────────────────────────────────

variable "alert_emails" {
  description = "Addresses for uptime + infrastructure alerts."
  type        = list(string)
  default     = []
}

variable "labels" {
  type = map(string)
  default = {
    app        = "fluidbox"
    managed-by = "terraform"
    stack      = "platform"
  }
}

variable "cluster_deletion_protection" {
  description = <<-EOT
    Guards the GKE cluster against deletion, including the delete+create a
    `datapath_provider` change forces.

    Default TRUE. Clearing it is a deliberate, recorded act - pass
    -var cluster_deletion_protection=false for the one apply that replaces the
    cluster, then restore it. That two-step is the point: an operator cannot
    replace the cluster by editing one unrelated field.
  EOT
  type        = bool
  default     = true
}
