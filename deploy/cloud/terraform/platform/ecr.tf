# One private repo: the replay-runner image for the no-cost acceptance replay
# (built locally arm64, pushed by scripts/cloud/replay-on-cluster.sh). The
# product images stay on GHCR — the release publishes multi-arch manifests, so
# t4g nodes pull them directly with no mirror.

resource "aws_ecr_repository" "replay_runner" {
  name                 = "fluidbox-replay-runner"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = false
  }
}

# M1.0 "ECR lifecycle rules": never accumulate replay-image layers.
resource "aws_ecr_lifecycle_policy" "replay_runner" {
  repository = aws_ecr_repository.replay_runner.name
  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "keep last 5 images"
      selection = {
        tagStatus   = "any"
        countType   = "imageCountMoreThan"
        countNumber = 5
      }
      action = { type = "expire" }
    }]
  })
}
