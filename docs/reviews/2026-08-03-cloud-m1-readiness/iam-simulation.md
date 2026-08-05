# IAM policy simulation — deployer + operator

Run 2026-08-03T18:37:38Z by `scripts/cloud/iam-simulate.sh`.
Policies extracted from a live `terraform plan` (no fixture to drift),
evaluated with `aws iam simulate-custom-policy` — a READ-ONLY API call.
Nothing was created.

Result: **42 passed, 0 failed**.

| case | action | expected | AWS decision |
|---|---|---|---|
| vpc create | `ec2:CreateVpc` | allowed | allowed |
| subnet create | `ec2:CreateSubnet` | allowed | allowed |
| security group create | `ec2:CreateSecurityGroup` | allowed | allowed |
| eks cluster create | `eks:CreateCluster` | allowed | allowed |
| eks nodegroup create | `eks:CreateNodegroup` | allowed | allowed |
| eks addon create | `eks:CreateAddon` | allowed | allowed |
| pod identity assoc | `eks:CreatePodIdentityAssociation` | allowed | allowed |
| eks describe (app stack data source) | `eks:DescribeCluster` | allowed | allowed |
| asg tag (autoscaler discovery) | `autoscaling:CreateOrUpdateTags` | allowed | allowed |
| elbv2 describe (edge data source) | `elasticloadbalancing:DescribeLoadBalancers` | allowed | allowed |
| kms key create | `kms:CreateKey` | allowed | allowed |
| kms alias create | `kms:CreateAlias` | allowed | allowed |
| cloudfront distribution create | `cloudfront:CreateDistribution` | allowed | allowed |
| eks log group create | `logs:CreateLogGroup` | allowed | allowed |
| log retention policy | `logs:PutRetentionPolicy` | allowed | allowed |
| ecr repo create | `ecr:CreateRepository` | allowed | allowed |
| ssm custody write | `ssm:PutParameter` | allowed | allowed |
| tag discovery (ALB lookup by scripts) | `tag:GetResources` | allowed | allowed |
| root-key check (verify-bootstrap) | `iam:GetAccountSummary` | allowed | allowed |
| state object read | `s3:GetObject` | allowed | allowed |
| role create under /fluidbox-cloud/ | `iam:CreateRole` | allowed | allowed |
| PassRole to EKS | `iam:PassRole` | allowed | allowed |
| PassRole to Pod Identity | `iam:PassRole` | allowed | allowed |
| role create OUTSIDE the path | `iam:CreateRole` | denied | implicitDeny |
| PassRole to an arbitrary service | `iam:PassRole` | denied | implicitDeny |
| PassRole for a NON-fluidbox role | `iam:PassRole` | denied | implicitDeny |
| read ANOTHER project's S3 bucket | `s3:GetObject` | denied | implicitDeny |
| delete a user (privilege escalation) | `iam:DeleteUser` | denied | implicitDeny |
| attach an admin policy to itself | `iam:AttachUserPolicy` | denied | implicitDeny |
| ec2 outside the pinned region | `ec2:CreateVpc` | denied | implicitDeny |
| write another project's SSM | `ssm:PutParameter` | denied | implicitDeny |
| assume the deployer role | `sts:AssumeRole` | allowed | allowed |
| terraform state write (BACKEND runs as operator) | `s3:PutObject` | allowed | allowed |
| state lockfile write | `s3:PutObject` | allowed | allowed |
| state bucket list | `s3:ListBucket` | allowed | allowed |
| kubeconfig bootstrap | `eks:DescribeCluster` | allowed | allowed |
| build infrastructure directly | `ec2:CreateVpc` | denied | implicitDeny |
| create an EKS cluster directly | `eks:CreateCluster` | denied | implicitDeny |
| read the CloudTrail bucket | `s3:GetObject` | denied | implicitDeny |
| escalate its own privileges | `iam:AttachUserPolicy` | denied | implicitDeny |

The negative cases matter as much as the positive ones: they are what
prove the scoping actually scopes in a SHARED account, rather than the
policy merely looking narrow. In particular the deployer cannot touch
another project's roles, buckets or parameters, cannot pass a role to an
arbitrary service, and cannot operate outside the pinned region.
