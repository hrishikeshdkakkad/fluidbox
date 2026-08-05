variable "region" {
  type    = string
  default = "us-east-1"
}

variable "deployer_role_arn" {
  description = "The bootstrap stack's scoped deployer role. Every apply of this stack assumes it — root applies fail by construction."
  type        = string
  default     = "arn:aws:iam::471112572248:role/fluidbox-cloud/fluidbox-cloud-deployer"
}

variable "cluster_name" {
  type    = string
  default = "fluidbox-cloud"
}

variable "cni" {
  description = "Cluster CNI: 'vpc-cni' (the original M1 recipe, netpol via the VPC CNI agent) or 'cilium' (ENI IPAM + native routing — the network-grants substrate; see cilium.tf for the full rationale and the live-rollout order)."
  type        = string
  default     = "vpc-cni"
  validation {
    condition     = contains(["vpc-cni", "cilium"], var.cni)
    error_message = "cni must be 'vpc-cni' or 'cilium'."
  }
}

variable "cilium_chart_version" {
  description = "Cilium helm chart version. 1.19.6 is the line every network-grants assertion was validated against (kind 37/38 + the substrate spike) — bump only with a revalidation."
  type        = string
  default     = "1.19.6"
}

variable "kubernetes_version" {
  description = <<-EOT
    RECIPE DELTA, decided 2026-08-03: the acceptance runs proved 1.33, but EKS
    moved 1.33 into EXTENDED support on 2026-07-28 — $0.60/cluster-hour instead
    of $0.10, i.e. +$365/mo, which would swamp the ~$131 idle floor. 1.35 is in
    STANDARD support until 2027-03-26 (verified live via
    `aws eks describe-cluster-versions` on 2026-08-03). The recipe's
    version-agnostic parts (VPC CNI network-policy standard mode, AZ pinning
    off us-east-1a, gp3, arm64) are preserved; upgrade_policy=STANDARD below
    additionally refuses to let the cluster ever age into extended billing
    silently.
  EOT
  type        = string
  default     = "1.35"
}

variable "operator_cidrs" {
  description = "REQUIRED (no default on purpose): CIDRs allowed to reach the EKS public API endpoint — the operator workstation(s). The M1 brief mandates a restricted endpoint."
  type        = list(string)

  # An empty list makes EKS fall back to 0.0.0.0/0 — i.e. a world-open API
  # server produced by omission rather than intent. The brief mandates a
  # RESTRICTED endpoint, so refuse both the empty list and the explicit
  # open-world CIDR at plan time rather than discovering it in an audit.
  validation {
    condition     = length(var.operator_cidrs) > 0
    error_message = "operator_cidrs must not be empty: EKS treats an empty list as 0.0.0.0/0, silently world-opening the API server."
  }

  validation {
    condition     = !contains(var.operator_cidrs, "0.0.0.0/0")
    error_message = "operator_cidrs must not contain 0.0.0.0/0. If a fully public API endpoint is genuinely wanted, remove this validation deliberately and record the decision."
  }
}

variable "vpc_cidr" {
  description = "10.42/16 avoids this shared account's two existing 10.0.0.0/16 VPCs (survey 2026-08-03)."
  type        = string
  default     = "10.42.0.0/16"
}

variable "azs" {
  description = "Two AZs (EKS minimum), us-east-1a excluded per the proven recipe (IPAM bring-up failures there on 2026-07-17)."
  type        = list(string)
  default     = ["us-east-1b", "us-east-1c"]
}

variable "node_az_index" {
  description = "Index into azs for the single-AZ node subnets pin (recipe: known-good AZ; also avoids cross-AZ data charges and RWO volume/pod split)."
  type        = number
  default     = 0
}

variable "system_instance_type" {
  description = <<-EOT
    RECIPE DELTA, forced by a live OOMKill on 2026-08-03. The proven recipe's
    t4g.medium (4 GiB raw, ~3.2 GiB allocatable) was validated with the chart's
    BUNDLED LiteLLM. M1 needs the DB-BACKED image instead — per-tenant virtual
    keys are a Postgres-backed LiteLLM feature, and hosted + shared-key mode is
    a deliberate 503 in core — and that image runs prisma at startup. With
    kube-system already requesting ~1.6 GiB, only ~1.6 GiB remained; LiteLLM
    was OOMKilled (exit 137) before it logged a single line, and node limits
    were already 186% overcommitted.

    t4g.large (8 GiB) fits server (1 GiB) + LiteLLM (2 GiB) + system pods with
    headroom, and stays on Graviton. COST: ~$49/mo instead of ~$24.50, moving
    the idle floor from ~$131 to ~$156 — recorded in
    docs/hosted/cloud-cost-model.md rather than absorbed silently.
  EOT
  type        = string
  default     = "t4g.large"
}

variable "sandbox_instance_type" {
  type    = string
  default = "t4g.medium"
}

variable "system_nodes_max" {
  description = "System nodegroup ceiling. 1/1/2: one node is the declared beta availability tier; 2 covers a replacement-during-drain."
  type        = number
  default     = 2
}

variable "sandbox_nodes_max" {
  description = "Sandbox nodegroup ceiling (scale-from-zero). 4 × t4g.medium ≈ 8 vCPU/16Gi — comfortably above the starter sandbox ResourceQuota."
  type        = number
  default     = 4
}

variable "eks_log_retention_days" {
  description = "Control-plane log retention (M1.0 'log retention rules'). The log group is precreated so EKS adopts it WITH retention (the survey found two old never-expire EKS groups — that mistake, not repeated)."
  type        = number
  default     = 30
}

variable "alb_controller_chart_version" {
  description = "eks/aws-load-balancer-controller chart pin (resolved live 2026-08-03)."
  type        = string
  default     = "3.4.3"
}

variable "cluster_autoscaler_chart_version" {
  description = "autoscaler/cluster-autoscaler chart pin — 9.59.0 ships app 1.35.0, matching kubernetes_version's minor (CA version-skew policy)."
  type        = string
  default     = "9.59.0"
}
