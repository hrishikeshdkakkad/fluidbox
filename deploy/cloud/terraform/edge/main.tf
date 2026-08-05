provider "aws" {
  region = var.region

  assume_role {
    role_arn     = var.deployer_role_arn
    session_name = "fluidbox-edge-apply"
  }

  default_tags {
    tags = {
      project          = "fluidbox"
      "fluidbox-cloud" = "m1"
      "managed-by"     = "terraform"
      stack            = "edge"
    }
  }
}

# The ALB the AWS Load Balancer Controller created for the chart's Ingress
# (fluidbox/fluidbox-server). Discovered by the controller's own tags so this
# stack never hand-builds or guesses load balancer identity.
data "aws_lb" "ingress" {
  tags = {
    "ingress.k8s.aws/stack" = "fluidbox/fluidbox-server"
    "elbv2.k8s.aws/cluster" = var.cluster_name
  }
}

# CloudFront → ALB, locked two ways:
#   1. The ALB's frontend SG admits only CloudFront's origin-facing prefix
#      list (platform stack) — the internet cannot reach the ALB directly.
#   2. This origin sends a secret custom header which an Ingress conditions
#      annotation requires — ANOTHER CloudFront distribution pointed at our
#      ALB is refused. The header value in Terraform is a PLACEHOLDER, ignored
#      after create: scripts/cloud/rotate-origin-secret.sh owns the real value
#      (CloudFront side + Ingress side + SSM record), so no secret lands in
#      state (PLAN rev 3 §P0).
#
# No custom domain in M1: the default *.cloudfront.net cert is the public TLS
# endpoint, and the origin leg is http-only (there is no certificate an ALB
# could present for its own *.elb.amazonaws.com name) — acceptable because the
# origin leg carries the SG + header locks above and rides AWS's network.
#
# SSE: CachingDisabled + AllViewerExceptHostHeader pass streams through
# unbuffered; origin_read_timeout=60 bounds the QUIET gap between bytes, and
# the server's 15s keepalive stays far inside it. ALB idle timeout is 120s
# (chart values). Streams are duration-unlimited while bytes flow.

resource "aws_cloudfront_distribution" "api" {
  enabled         = true
  comment         = "fluidbox-cloud API edge (M1)"
  is_ipv6_enabled = true
  price_class     = "PriceClass_100"
  http_version    = "http2"

  origin {
    origin_id   = "fluidbox-alb"
    domain_name = data.aws_lb.ingress.dns_name

    custom_origin_config {
      http_port                = 80
      https_port               = 443
      origin_protocol_policy   = "http-only"
      origin_ssl_protocols     = ["TLSv1.2"]
      origin_read_timeout      = 60
      origin_keepalive_timeout = 60
    }

    custom_header {
      name  = "x-fluidbox-origin-auth"
      value = "rotate-me-immediately" # placeholder; rotation script owns the real value
    }
  }

  default_cache_behavior {
    target_origin_id       = "fluidbox-alb"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods         = ["GET", "HEAD"]
    compress               = true

    # AWS managed policies: CachingDisabled + AllViewerExceptHostHeader (the
    # Host header must become the origin's own or the ALB rule set would need
    # host awareness; everything else — auth, cookies, query — passes).
    cache_policy_id          = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"
    origin_request_policy_id = "b689b0a8-53d0-40ab-baf2-68738e2966ac"
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }

  lifecycle {
    # The rotation script owns the origin header after create.
    ignore_changes = [origin]
  }
}
