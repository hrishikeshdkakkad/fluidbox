# Bootstrap — M1.0 guardrails (the one root-credential apply)

This stack is the **only** Terraform ever applied with the account root
credentials. It creates the guardrails that gate everything else in
`docs/plans/2026-08-03-fluidbox-cloud-m1-brief.md` §M1.0:

- encrypted + versioned + lockfile-locked Terraform state (S3-native lock, no DynamoDB);
- the `fluidbox-operator` IAM user and the scoped `fluidbox-cloud-deployer` role
  (path-confined IAM writes, tight `iam:PassRole`, named-resource scoping — see
  `iam.tf`'s header for the model and its recorded residuals);
- two budgets (tag-filtered `fluidbox-cloud-monthly` + `fluidbox-account-breaker`)
  with email + SNS notifications;
- an owned CloudTrail (`fluidbox-cloud`, multi-region, log-file validation ON,
  90-day lifecycle) — see `cloudtrail.tf` for the honest second-copy cost note;
- the `fluidbox-root-activity` EventBridge alarm (any root use → email).

**No secret values land in state**: this stack creates no access keys, no
passwords, no tokens. The operator's access key is created in the console and
never touches Terraform.

## The ceremony

Pre-req: `aws sts get-caller-identity` shows `arn:aws:iam::<account>:root`
(this is the last sanctioned use of that key), and the two USER DECISIONS are
made (`account_budget_limit`, `fluidbox_budget_limit` —
`docs/plans/2026-08-03-cloud-m1-decisions.md`).

```bash
cd deploy/cloud/terraform/bootstrap
terraform init
terraform plan  -var account_budget_limit=400          # review — per-action user approval required
terraform apply -var account_budget_limit=400          # THE root apply
```

If `aws_ce_cost_allocation_tag.project` fails ("tag not found"): the tag has
never been seen on billed usage yet. Re-run with
`-var activate_cost_allocation_tag=false`, then flip it back `true` and
re-apply ~24h after the first tagged resource exists. Until then the
account-wide budget is the working breaker (it always is).

Then, in order:

1. **Confirm the SNS email** (SNS sends a confirmation link; the subscription
   is dead until clicked). Budget emails additionally go direct to the address.
2. **Migrate state into the bucket it just created**: uncomment `backend.tf`,
   then `terraform init -migrate-state` (answer yes), then delete the local
   `terraform.tfstate*` files.
3. **Create the operator access key** — root console → IAM → Users →
   `fluidbox-operator` → Security credentials → Create access key (CLI).
   Optionally also set a console password + MFA now.
4. **Configure profiles** in `~/.aws/config`:

   ```ini
   [profile fluidbox-operator]
   region = us-east-1
   # credentials for the fluidbox-operator user go in ~/.aws/credentials

   [profile fluidbox-deployer]
   role_arn = arn:aws:iam::471112572248:role/fluidbox-cloud/fluidbox-cloud-deployer
   source_profile = fluidbox-operator
   region = us-east-1
   # after MFA hardening (step 7): mfa_serial = arn:aws:iam::471112572248:mfa/<device>
   ```

5. **Verify the scoped path works** (also proves §9 criterion 1's mechanism):

   ```bash
   AWS_PROFILE=fluidbox-deployer aws sts get-caller-identity   # assumed-role/fluidbox-cloud-deployer
   AWS_PROFILE=fluidbox-deployer terraform plan                # zero diff
   scripts/cloud/verify-bootstrap.sh                           # full check incl. root-key presence
   ```

6. **RETIRE THE ROOT ACCESS KEY.** Root console → account menu → Security
   credentials → Access keys → **Deactivate**. Re-run step 5 and one platform
   `terraform plan` with the deactivated key still in place; when nothing
   breaks for a day, **Delete** the key. Remove it from `~/.aws/credentials`
   (`[default]`) too. Root keeps: console password + MFA (break-glass only —
   every use now emails via `fluidbox-root-activity`).
7. **Harden (recommended, after operator MFA enrollment)**: apply with
   `-var require_deployer_mfa=true` and add `mfa_serial` to the deployer
   profile.

## After retirement

- Platform/app/edge applies: `AWS_PROFILE=fluidbox-deployer` (they refuse root —
  each stack's provider pins the assumed role).
- Routine budget tuning: the deployer role can `budgets:ModifyBudget` on
  `fluidbox-*` budgets — edit the variable here and apply *with the deployer
  profile* (this stack's resources are deliberately deployer-adjustable only
  for budgets; IAM changes need break-glass).
- IAM/bootstrap changes: break-glass root **console** session (no key). The
  root-activity alarm announcing it is the control working, not a bug.
