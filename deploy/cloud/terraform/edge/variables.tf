variable "region" {
  type    = string
  default = "us-east-1"
}

variable "deployer_role_arn" {
  type    = string
  default = "arn:aws:iam::471112572248:role/fluidbox-cloud/fluidbox-cloud-deployer"
}

variable "cluster_name" {
  type    = string
  default = "fluidbox-cloud"
}
