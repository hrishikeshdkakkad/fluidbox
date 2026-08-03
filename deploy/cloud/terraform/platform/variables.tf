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
  description = "REQUIRED (no default on purpose): CIDRs allowed to reach the EKS public API endpoint — the operator workstation(s). The M1 brief mandates a restricted endpoint; 0.0.0.0/0 here is a decision, not a fallback."
  type        = list(string)
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
  type    = string
  default = "t4g.medium"
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
