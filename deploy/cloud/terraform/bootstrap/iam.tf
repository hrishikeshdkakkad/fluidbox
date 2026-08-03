# The scoped deployment identity that retires the root key.
#
# Shape: a human IAM user (fluidbox-operator) that can do exactly two things —
# assume the deployer role and self-manage its own credentials — and a deployer
# role (fluidbox-cloud-deployer) whose policies are scoped so the platform
# stacks can build EKS/edge WITHOUT being able to touch the OTHER projects that
# share this account (survey 2026-08-03: expenseforce, accountforce, fluidzero,
# temporalcommerce all live here).
#
# Scoping model:
#   - Every IAM role/policy the platform stacks create lives under the IAM path
#     /fluidbox-cloud/ — the deployer's IAM writes are confined to that path.
#   - iam:PassRole is restricted to /fluidbox-cloud/ roles AND to the three
#     services that legitimately receive them (EKS, EC2, Pod Identity).
#   - Named resources (S3, SNS, ECR, SSM, EventBridge, budgets, logs) are
#     confined to fluidbox-* / /fluidbox/ prefixes.
#   - KMS mutations require the project=fluidbox resource tag.
#   - ec2/eks/elbv2/autoscaling stay action-wide but region-locked: the EKS
#     lifecycle touches too many unnameable ARNs (ENIs, SGs, LTs) to enumerate.
#     RESIDUAL (recorded in docs/hosted/cloud-threat-model-m1.md): within
#     us-east-1 the deployer could affect other projects' EC2-plane resources;
#     accepted for a single trusted operator with CloudTrail on.

# ── operator user ───────────────────────────────────────────────────────────

resource "aws_iam_user" "operator" {
  name = var.operator_user_name
  path = "/fluidbox-cloud/"
}

resource "aws_iam_user_policy" "operator" {
  name = "fluidbox-operator-base"
  user = aws_iam_user.operator.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        Sid      = "AssumeDeployer"
        Effect   = "Allow"
        Action   = "sts:AssumeRole"
        Resource = aws_iam_role.deployer.arn
      },
      {
        Sid    = "SelfServiceCredentials"
        Effect = "Allow"
        Action = [
          "iam:ChangePassword",
          "iam:GetUser",
          "iam:CreateAccessKey",
          "iam:DeleteAccessKey",
          "iam:ListAccessKeys",
          "iam:UpdateAccessKey",
          "iam:GetAccessKeyLastUsed",
          "iam:ListMFADevices",
          "iam:EnableMFADevice",
          "iam:ResyncMFADevice",
          "iam:DeactivateMFADevice",
        ]
        Resource = aws_iam_user.operator.arn
      },
      {
        Sid      = "SelfServiceVirtualMfa"
        Effect   = "Allow"
        Action   = ["iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice"]
        Resource = "arn:aws:iam::${local.account_id}:mfa/${var.operator_user_name}"
      },
      ],
      # Budget visibility without assuming the role (handy from a phone/console).
      [{
        Sid      = "ViewBudgets"
        Effect   = "Allow"
        Action   = ["budgets:ViewBudget", "ce:GetCostAndUsage", "ce:GetCostForecast"]
        Resource = "*"
      }]
    )
  })
}

# ── deployer role ───────────────────────────────────────────────────────────

resource "aws_iam_role" "deployer" {
  name = var.deployer_role_name
  path = "/fluidbox-cloud/"
  # Terraform applies can exceed the default 1h (EKS create is 10-15 min per
  # wait, CloudFront ~5); 4h keeps one session per work session.
  max_session_duration = 14400

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "OperatorAssume"
      Effect = "Allow"
      Principal = {
        AWS = concat([aws_iam_user.operator.arn], var.extra_deployer_principal_arns)
      }
      Action    = "sts:AssumeRole"
      Condition = var.require_deployer_mfa ? { Bool = { "aws:MultiFactorAuthPresent" = "true" } } : {}
    }]
  })
}

# IAM-plane permissions: confined to the /fluidbox-cloud/ path.
resource "aws_iam_policy" "deployer_iam" {
  name = "fluidbox-cloud-deployer-iam"
  path = "/fluidbox-cloud/"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "RoleLifecycle"
        Effect = "Allow"
        Action = [
          "iam:CreateRole",
          "iam:DeleteRole",
          "iam:GetRole",
          "iam:UpdateRole",
          "iam:UpdateRoleDescription",
          "iam:UpdateAssumeRolePolicy",
          "iam:TagRole",
          "iam:UntagRole",
          "iam:PutRolePolicy",
          "iam:DeleteRolePolicy",
          "iam:GetRolePolicy",
          "iam:ListRolePolicies",
          "iam:ListAttachedRolePolicies",
          "iam:ListInstanceProfilesForRole",
          "iam:ListRoleTags",
        ]
        Resource = "arn:aws:iam::${local.account_id}:role/fluidbox-cloud/*"
      },
      {
        Sid      = "AttachOnlyKnownPolicies"
        Effect   = "Allow"
        Action   = ["iam:AttachRolePolicy", "iam:DetachRolePolicy"]
        Resource = "arn:aws:iam::${local.account_id}:role/fluidbox-cloud/*"
        Condition = {
          ArnLike = {
            "iam:PolicyARN" = [
              "arn:aws:iam::aws:policy/*",
              "arn:aws:iam::${local.account_id}:policy/fluidbox-cloud/*",
            ]
          }
        }
      },
      {
        Sid    = "PolicyLifecycle"
        Effect = "Allow"
        Action = [
          "iam:CreatePolicy",
          "iam:DeletePolicy",
          "iam:GetPolicy",
          "iam:GetPolicyVersion",
          "iam:ListPolicyVersions",
          "iam:CreatePolicyVersion",
          "iam:DeletePolicyVersion",
          "iam:TagPolicy",
          "iam:UntagPolicy",
          "iam:ListPolicyTags",
        ]
        Resource = "arn:aws:iam::${local.account_id}:policy/fluidbox-cloud/*"
      },
      {
        Sid      = "ReadAwsManagedPolicies"
        Effect   = "Allow"
        Action   = ["iam:GetPolicy", "iam:GetPolicyVersion", "iam:ListPolicyVersions"]
        Resource = "arn:aws:iam::aws:policy/*"
      },
      {
        Sid    = "InstanceProfiles"
        Effect = "Allow"
        Action = [
          "iam:CreateInstanceProfile",
          "iam:DeleteInstanceProfile",
          "iam:GetInstanceProfile",
          "iam:AddRoleToInstanceProfile",
          "iam:RemoveRoleFromInstanceProfile",
          "iam:TagInstanceProfile",
        ]
        Resource = "arn:aws:iam::${local.account_id}:instance-profile/fluidbox-cloud/*"
      },
      {
        Sid      = "PassRoleScoped"
        Effect   = "Allow"
        Action   = "iam:PassRole"
        Resource = "arn:aws:iam::${local.account_id}:role/fluidbox-cloud/*"
        Condition = {
          StringEquals = {
            "iam:PassedToService" = [
              "eks.amazonaws.com",
              "ec2.amazonaws.com",
              "pods.eks.amazonaws.com",
            ]
          }
        }
      },
      {
        Sid      = "ServiceLinkedRoles"
        Effect   = "Allow"
        Action   = "iam:CreateServiceLinkedRole"
        Resource = "arn:aws:iam::${local.account_id}:role/aws-service-role/*"
        Condition = {
          StringEquals = {
            "iam:AWSServiceName" = [
              "eks.amazonaws.com",
              "eks-nodegroup.amazonaws.com",
              "elasticloadbalancing.amazonaws.com",
              "autoscaling.amazonaws.com",
              "spot.amazonaws.com",
            ]
          }
        }
      },
      {
        Sid      = "ReadServiceLinkedRoles"
        Effect   = "Allow"
        Action   = ["iam:GetRole", "iam:ListAttachedRolePolicies", "iam:ListRolePolicies"]
        Resource = "arn:aws:iam::${local.account_id}:role/aws-service-role/*"
      },
    ]
  })
}

# Infra-plane permissions. See the scoping-model note at the top of this file.
resource "aws_iam_policy" "deployer_infra" {
  name = "fluidbox-cloud-deployer-infra"
  path = "/fluidbox-cloud/"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ComputePlaneRegionLocked"
        Effect = "Allow"
        Action = [
          "ec2:*",
          "eks:*",
          "elasticloadbalancing:*",
          "autoscaling:*",
        ]
        Resource  = "*"
        Condition = { StringEquals = { "aws:RequestedRegion" = var.region } }
      },
      {
        Sid    = "KmsRead"
        Effect = "Allow"
        Action = [
          "kms:CreateKey",
          "kms:ListKeys",
          "kms:ListAliases",
          "kms:DescribeKey",
          "kms:GetKeyPolicy",
          "kms:GetKeyRotationStatus",
          "kms:ListResourceTags",
          "kms:TagResource",
        ]
        Resource = "*"
      },
      {
        Sid    = "KmsMutateTagged"
        Effect = "Allow"
        Action = [
          "kms:EnableKeyRotation",
          "kms:DisableKeyRotation",
          "kms:PutKeyPolicy",
          "kms:ScheduleKeyDeletion",
          "kms:CancelKeyDeletion",
          "kms:UpdateKeyDescription",
          "kms:UntagResource",
        ]
        Resource  = "*"
        Condition = { StringEquals = { "aws:ResourceTag/project" = "fluidbox" } }
      },
      {
        Sid    = "KmsAliases"
        Effect = "Allow"
        Action = ["kms:CreateAlias", "kms:DeleteAlias", "kms:UpdateAlias"]
        Resource = [
          "arn:aws:kms:${var.region}:${local.account_id}:alias/fluidbox-*",
          "arn:aws:kms:${var.region}:${local.account_id}:key/*",
        ]
      },
      {
        # CloudFront is global and largely un-scopable pre-create; distributions
        # we create are tagged project=fluidbox. Residual recorded in the threat
        # model (there were zero pre-existing distributions in the survey).
        Sid      = "CloudFront"
        Effect   = "Allow"
        Action   = ["cloudfront:*"]
        Resource = "*"
      },
      {
        Sid      = "CloudFrontPrefixListRead"
        Effect   = "Allow"
        Action   = ["ec2:DescribeManagedPrefixLists", "ec2:GetManagedPrefixListEntries"]
        Resource = "*"
      },
      {
        Sid    = "S3FluidboxBuckets"
        Effect = "Allow"
        Action = ["s3:*"]
        Resource = [
          "arn:aws:s3:::fluidbox-*",
          "arn:aws:s3:::fluidbox-*/*",
        ]
      },
      {
        Sid    = "LogsFluidbox"
        Effect = "Allow"
        Action = ["logs:*"]
        Resource = [
          "arn:aws:logs:${var.region}:${local.account_id}:log-group:/aws/eks/fluidbox-*",
          "arn:aws:logs:${var.region}:${local.account_id}:log-group:/aws/eks/fluidbox-*:*",
          "arn:aws:logs:${var.region}:${local.account_id}:log-group:/fluidbox/*",
          "arn:aws:logs:${var.region}:${local.account_id}:log-group:/fluidbox/*:*",
        ]
      },
      {
        Sid      = "LogsDescribe"
        Effect   = "Allow"
        Action   = ["logs:DescribeLogGroups", "logs:ListTagsForResource", "logs:ListTagsLogGroup"]
        Resource = "*"
      },
      {
        Sid      = "SnsFluidbox"
        Effect   = "Allow"
        Action   = ["sns:*"]
        Resource = "arn:aws:sns:${var.region}:${local.account_id}:fluidbox-*"
      },
      {
        Sid    = "EventsFluidbox"
        Effect = "Allow"
        Action = ["events:*"]
        Resource = [
          "arn:aws:events:${var.region}:${local.account_id}:rule/fluidbox-*",
        ]
      },
      {
        Sid    = "SsmFluidboxParams"
        Effect = "Allow"
        Action = [
          "ssm:PutParameter",
          "ssm:GetParameter",
          "ssm:GetParameters",
          "ssm:GetParametersByPath",
          "ssm:DeleteParameter",
          "ssm:AddTagsToResource",
          "ssm:ListTagsForResource",
        ]
        Resource = "arn:aws:ssm:${var.region}:${local.account_id}:parameter/fluidbox/*"
      },
      {
        Sid      = "SsmDescribe"
        Effect   = "Allow"
        Action   = ["ssm:DescribeParameters"]
        Resource = "*"
      },
      {
        Sid    = "EcrFluidbox"
        Effect = "Allow"
        Action = ["ecr:*"]
        Resource = [
          "arn:aws:ecr:${var.region}:${local.account_id}:repository/fluidbox-*",
        ]
      },
      {
        Sid      = "EcrAuth"
        Effect   = "Allow"
        Action   = ["ecr:GetAuthorizationToken"]
        Resource = "*"
      },
      {
        Sid      = "BudgetsFluidbox"
        Effect   = "Allow"
        Action   = ["budgets:ViewBudget", "budgets:ModifyBudget"]
        Resource = "arn:aws:budgets::${local.account_id}:budget/fluidbox-*"
      },
      {
        Sid    = "ReadOnlyPlaneWide"
        Effect = "Allow"
        Action = [
          "ce:Get*",
          "ce:Describe*",
          "ce:List*",
          "pricing:*",
          "servicequotas:Get*",
          "servicequotas:List*",
          "cloudtrail:Get*",
          "cloudtrail:Describe*",
          "cloudtrail:List*",
          "cloudtrail:LookupEvents",
          "health:Describe*",
          "sts:GetCallerIdentity",
          # Resource discovery by tag: how rotate-origin-secret.sh and
          # teardown.sh find the controller-created ALB (its ARN is not in any
          # Terraform state). Read-only and un-scopable by design.
          "tag:GetResources",
          "tag:GetTagKeys",
          "tag:GetTagValues",
          # verify-bootstrap.sh reads AccountAccessKeysPresent to prove the
          # root key is retired. Account-summary is counts only — it exposes no
          # principal, policy, or credential material.
          "iam:GetAccountSummary",
        ]
        Resource = "*"
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "deployer_iam" {
  role       = aws_iam_role.deployer.name
  policy_arn = aws_iam_policy.deployer_iam.arn
}

resource "aws_iam_role_policy_attachment" "deployer_infra" {
  role       = aws_iam_role.deployer.name
  policy_arn = aws_iam_policy.deployer_infra.arn
}
