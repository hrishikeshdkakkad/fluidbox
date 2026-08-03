# State backend — TWO-PHASE by necessity (the bucket this stack creates cannot
# hold the state of its own first apply):
#
#   Phase 1 (first apply): leave this block commented. State is local
#     (terraform.tfstate in this directory — gitignored).
#   Phase 2 (immediately after the first apply): uncomment, then run
#       terraform init -migrate-state
#     and answer "yes". Delete the local terraform.tfstate* files afterwards.
#
# The bucket name is fluidbox-cloud-tfstate-<account-id>; the first apply
# prints it as the `state_bucket` output.

# terraform {
#   backend "s3" {
#     bucket       = "fluidbox-cloud-tfstate-471112572248"
#     key          = "bootstrap.tfstate"
#     region       = "us-east-1"
#     encrypt      = true
#     use_lockfile = true
#   }
# }
