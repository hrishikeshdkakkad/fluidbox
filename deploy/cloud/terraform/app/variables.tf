variable "region" {
  type    = string
  default = "us-east-1"
}

variable "deployer_role_arn" {
  type    = string
  default = "arn:aws:iam::471112572248:role/fluidbox-cloud/fluidbox-cloud-deployer"
}

variable "chart_version" {
  description = "The released fluidbox chart (OCI, ghcr) — UNCHANGED by M1. Images default to the chart appVersion (multi-arch on GHCR)."
  type        = string
  default     = "0.4.0"
}

variable "public_url" {
  description = <<-EOT
    FLUIDBOX_PUBLIC_URL — the browser/AS-facing origin. STAGED on purpose:
      M1.1 (first apply): "" — no browser flows yet; the replay acceptance
             drives the admin API through CloudFront with a bearer token.
      after the edge stack: "https://<cloudfront-domain>" if CLI/PAT OAuth
             surfaces are wanted on the API host.
      M1.2 (Vercel dashboard live): "https://<vercel-origin>" — the login
             callback + __Host-fbx_web cookie land on the Vercel origin via
             the sso rewrites. NEVER a host.docker.internal-ish internal URL.
    Changing it is a helm values change (terraform apply), not a chart change.
  EOT
  type        = string
  default     = ""
}

variable "require_sso" {
  description = <<-EOT
    STAGED (see docs/hosted/cloud-onboarding-checklist.md): false for the M1.1
    platform gate — single-user mode lets the admin token drive the no-cost
    replay acceptance end to end. Flip to true in the M1.2 onboarding apply:
    multi-user identity on, admin token confined to /v1/admin/* (exactly the
    operator onboarding surface), browsers authenticate per-org OIDC.
  EOT
  type        = bool
  default     = false
}

variable "litellm_image" {
  description = "DB-backed LiteLLM image (the -database variant carries the prisma client that /key/* virtual keys need). Pin a digest for production parity with the compose files."
  type        = string
  default     = "ghcr.io/berriai/litellm-database:main-stable"
}

variable "llm_tenant_models" {
  description = "FLUIDBOX_LLM_TENANT_MODELS (CSV allowlist on minted tenant keys). Haiku-only is the standing cost-discipline agreement."
  type        = string
  default     = "claude-haiku-4-5"
}

variable "llm_tenant_max_budget" {
  description = "FLUIDBOX_LLM_TENANT_MAX_BUDGET (USD, rolling window below)."
  type        = string
  default     = "5"
}

variable "llm_tenant_budget_duration" {
  description = "FLUIDBOX_LLM_TENANT_BUDGET_DURATION — rolling, NOT calendar-month (documented quota gap)."
  type        = string
  default     = "30d"
}

variable "default_model" {
  type    = string
  default = "claude-haiku-4-5"
}

variable "helm_timeout_seconds" {
  description = "helm wait budget: Neon boot migrations + image pull on a cold node."
  type        = number
  default     = 900
}

variable "litellm_memory_limit" {
  description = "LiteLLM container memory limit. 4Gi, not the bundled image's 2Gi: the DB-backed variant runs prisma at startup and was OOMKilled at 2Gi on a node that was only 22% committed (2026-08-03, live)."
  type        = string
  default     = "4Gi"
}

variable "litellm_memory_request" {
  description = "LiteLLM memory request (scheduling floor; the limit above is what prisma actually needs at boot)."
  type        = string
  default     = "1Gi"
}
