# Network per PLAN rev 3 §Edge/network: PUBLIC subnets only, nodes carry a
# public IP, tight security groups, and **no NAT ever** — a NAT gateway would
# add ~$32/mo + $0.045/GB and blow the verified ~$131 idle floor
# (docs/hosted/cloud-cost-model.md). Nodes need egress (Neon, GHCR, model
# APIs); sandbox PODS stay zeroEgress-constrained by the chart's NetworkPolicy
# regardless of node egress — the node's network posture is not the sandbox
# security boundary and never was.

resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "${var.cluster_name}-vpc" }
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id
  tags   = { Name = "${var.cluster_name}-igw" }
}

resource "aws_subnet" "public" {
  count                   = length(var.azs)
  vpc_id                  = aws_vpc.this.id
  availability_zone       = var.azs[count.index]
  cidr_block              = cidrsubnet(var.vpc_cidr, 4, count.index)
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.cluster_name}-public-${var.azs[count.index]}"
    # ALB controller subnet discovery (internet-facing), plus the cluster
    # ownership tag some controllers still expect.
    "kubernetes.io/role/elb"                    = "1"
    "kubernetes.io/cluster/${var.cluster_name}" = "shared"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id
  tags   = { Name = "${var.cluster_name}-public" }
}

resource "aws_route" "public_igw" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.this.id
}

resource "aws_route_table_association" "public" {
  count          = length(aws_subnet.public)
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# ── ALB frontend security group ─────────────────────────────────────────────
# BYO frontend SG for the chart's Ingress (annotation
# alb.ingress.kubernetes.io/security-groups): ONLY CloudFront's origin-facing
# address space may reach the ALB, on :80 (TLS terminates at CloudFront; with
# no custom domain there is no cert the ALB could present). The rotating
# origin header (edge stack + scripts/cloud/rotate-origin-secret.sh) covers
# the residual "someone else's CloudFront distribution" path.

data "aws_ec2_managed_prefix_list" "cloudfront_origin" {
  name = "com.amazonaws.global.cloudfront.origin-facing"
}

resource "aws_security_group" "alb_frontend" {
  name        = "fluidbox-alb-frontend"
  description = "fluidbox ALB: CloudFront origin-facing only"
  vpc_id      = aws_vpc.this.id

  ingress {
    description     = "CloudFront origin-facing, HTTP (TLS terminates at CloudFront)"
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    prefix_list_ids = [data.aws_ec2_managed_prefix_list.cloudfront_origin.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "fluidbox-alb-frontend" }
}
