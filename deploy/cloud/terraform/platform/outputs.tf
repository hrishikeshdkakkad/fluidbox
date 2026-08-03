output "cluster_name" {
  value = aws_eks_cluster.this.name
}

output "cluster_endpoint" {
  value = aws_eks_cluster.this.endpoint
}

output "vpc_id" {
  value = aws_vpc.this.id
}

output "alb_frontend_sg_id" {
  description = "BYO frontend SG for the chart Ingress annotation (app stack reads this via remote state)."
  value       = aws_security_group.alb_frontend.id
}

output "kms_kek_arn" {
  description = "FLUIDBOX_KMS_AWS_KEY_ID for the server extraEnv (app stack reads this via remote state). Custody roots here — never delete without docs/hosted/kms-operations.md."
  value       = aws_kms_key.kek.arn
}

output "replay_ecr_repo_url" {
  value = aws_ecr_repository.replay_runner.repository_url
}

output "kubeconfig_hint" {
  value = "aws eks update-kubeconfig --name ${aws_eks_cluster.this.name} --region ${var.region} --role-arn ${var.deployer_role_arn} --alias fluidbox-cloud"
}
