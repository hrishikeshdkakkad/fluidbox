output "cloudfront_domain" {
  description = "The public API host (CLI/PAT traffic; also FLUIDBOX_API_URL for the Vercel build)."
  value       = aws_cloudfront_distribution.api.domain_name
}

output "distribution_id" {
  description = "For rotate-origin-secret.sh + cache ops."
  value       = aws_cloudfront_distribution.api.id
}

output "alb_dns_name" {
  description = "Origin ALB — direct requests here must be REFUSED (SG + header rule); scripts/cloud/direct-alb-check.sh proves it."
  value       = data.aws_lb.ingress.dns_name
}

output "post_apply" {
  value = "REQUIRED next step: scripts/cloud/rotate-origin-secret.sh — the placeholder origin header is not a lock until rotated (it also installs the Ingress conditions annotation)."
}
