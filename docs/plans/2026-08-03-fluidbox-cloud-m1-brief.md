# Fluidbox Cloud M1 — Managed Private Beta

**Status:** Draft implementation brief
**Scope:** M1 only
**Target:** A small, invited, operator-managed private beta
**Core constraint:** No Fluidbox Core changes and no Helm chart changes
**Parent plan:** `docs/plans/2026-08-03-fluidbox-cloud-plan.md` (PLAN rev 3)

## 1. Executive summary

M1 proves that the existing self-hosted Fluidbox product can be operated by the Fluidbox team as a managed service on AWS.

The milestone does **not** build the complete self-service Fluidbox Cloud product. Customers are onboarded manually by an operator. The operator creates the tenant, configures identity and model access, verifies login, and hands the customer access to the existing dashboard.

M1 is successful when an invited customer can sign in, submit a governed run, watch it through the public edge, complete an approval, retrieve the result, and leave no sandbox compute running when idle. The deployment must also have working cost guardrails, tenant isolation, network enforcement, operational alarms, and documented containment procedures.

In one sentence:

> Deploy today's Fluidbox safely, operate it for a few real customers, and collect evidence that the platform is ready to become self-service later.

## 2. Objective

Answer the following question with real-environment evidence:

> Can Fluidbox reliably operate its existing product for approximately five to ten manually onboarded organizations on one managed AWS deployment?

M1 optimizes for:

- preserving the proven Fluidbox Core and Kubernetes execution model;
- reaching a usable private beta with the smallest new product surface;
- learning how the platform behaves under real operations;
- establishing AWS security and cost controls before broader deployment;
- keeping all later self-service work outside the security authority of Core.

## 3. Product boundary

### Included in M1

- A persistent Fluidbox Core deployment on Amazon EKS.
- The existing Helm chart, unchanged, with its bundled web deployment disabled.
- The existing Kubernetes sandbox provider and network restrictions.
- A Vercel-hosted dashboard that reaches Core through controlled proxy routes.
- A CloudFront and ALB public API edge.
- Neon Postgres for Core and a small database for LiteLLM.
- AWS KMS access through EKS Pod Identity.
- Manual creation and configuration of beta tenants.
- Manual per-organization OIDC/SSO setup.
- Existing Core-side run and LLM budget controls.
- Infrastructure-as-code, alarms, logs, budgets, and operator runbooks.
- Real replay-run, approval, streaming, isolation, and idle-scaling evidence.

### Explicitly deferred

The following are not part of M1:

- Public signup or open self-service access.
- The new Fluidbox Cloud Lambda API.
- DynamoDB cloud-state tables.
- Automated provisioning sagas.
- Automated WorkOS organization or Connect-app creation.
- AuthKit-first onboarding and dual WorkOS/Core session orchestration.
- Self-service organization discovery, membership, invitations, or role management.
- Hosted plan and billing records.
- A customer-facing usage dashboard or usage-rollup jobs.
- Atomic per-tenant concurrent-run limits.
- Monthly compute-credit enforcement.
- Tenant suspend and reactivate operations.
- Purge and hosted-retention workflows.
- Alternative execution providers or scale-to-zero Core infrastructure.

These capabilities belong to M2, M3, or M4. Their absence is the reason M1 remains an invited, trusted private beta.

## 4. Architecture

```text
Invited user
    |
    v
Vercel dashboard
    |  browser login, API proxy, event stream
    v
CloudFront -> AWS ALB -> Fluidbox Core on EKS
                              |        |
                              |        +--> LiteLLM
                              |
                              +--> Per-run sandbox pods
                              |
                              +--> Neon Postgres

Fluidbox operator
    |
    +--> Terraform/AWS operations
    +--> Existing Core admin APIs for tenant onboarding
```

### Authority model

Fluidbox Core remains the only authority for:

- tenants and memberships;
- roles, sessions, and personal access tokens;
- agents, policies, runs, and approvals;
- credentials and model access;
- raw usage records.

M1 introduces no shared authorization database and no Cloud-owned copy of tenant permissions. AWS and Vercel provide hosting and routing; they do not become alternative sources of Fluidbox authority.

### Execution model

Each run continues to use the existing Kubernetes execution provider. Core creates an isolated sandbox pod and applies the existing network posture, budgets, credentials, and governance controls. The sandbox node group may scale from zero when a run starts and return to zero when idle.

## 5. Identity and onboarding

M1 uses operator-assisted onboarding instead of a customer-facing provisioning system.

For each beta organization, the operator:

1. Reserves and verifies the organization slug.
2. Creates the tenant using an existing Core admin endpoint.
3. Creates or configures an organization-specific OIDC application.
4. Sends the OIDC client secret once into Core's sealed custody.
5. Configures and verifies the initial owner.
6. Verifies the tenant's managed LLM key or other approved model access.
7. Tests the complete login path before sending the customer their tenant link.
8. Records the onboarding outcome in an operator-controlled ledger.

If WorkOS is used as the OIDC provider, M1 must prove the authentication behavior needed for the manually configured organization: nonce handling, PKCE compatibility, and enforcement of organization restriction. Automated WorkOS API provisioning, invitations, external-ID reconciliation, and AuthKit-first organization selection remain deferred.

M1 should use Core's existing organization-specific SSO flow. It should not introduce a second dashboard session solely for future self-service onboarding.

## 6. Delivery phases

### M1.0 — Guardrails and feasibility proofs

Establish safety controls before deploying the platform:

- Bootstrap a scoped AWS deployment role and retire root-key usage.
- Restrict `iam:PassRole` to the required deployment roles.
- Create encrypted, versioned, and locked Terraform state.
- Apply a tag-filtered Fluidbox budget.
- Retain an account-wide budget as a second circuit breaker.
- Enable CloudTrail and root-activity alarms.
- Define log retention and ECR/S3 lifecycle rules.
- Re-verify the idle and light-use cost model, including public IPv4 and ALB costs.
- Prove the manually configured OIDC login path.
- Probe Vercel proxy behavior for the Core cookie and long-lived server-sent events.
- Document the fallback if Vercel cannot reliably carry long-lived streams.

**Gate:** No EKS platform deployment proceeds until the scoped IAM path, budget controls, identity proof, streaming proof, and cost model are recorded as passing.

### M1.1 — Managed EKS platform

Deploy the existing Fluidbox platform:

- Create the VPC, EKS cluster, node groups, and required add-ons with Terraform.
- Use a small on-demand system node for Core and LiteLLM.
- Use a managed sandbox node group capable of scaling from zero.
- Preserve the existing Kubernetes network-policy behavior.
- Enable EKS control-plane logs and restrict API endpoint access.
- Configure gp3 storage and the declared beta-grade RWO availability tier.
- Configure EKS Pod Identity for KMS.
- Provision Neon and the small LiteLLM database.
- Install the unchanged Fluidbox Helm chart with `web.enabled=false`.
- Deploy the AWS Load Balancer Controller and use the chart's existing Ingress.
- Place CloudFront in front of the ALB.
- Restrict the ALB origin using the CloudFront prefix list and a rotating secret header.
- Verify that direct ALB requests are refused.

**Gate:** Core is healthy, the chart's existing tests pass, the public edge is locked down, and a no-cost replay run completes on the cluster.

### M1.2 — Operator onboarding and beta access

Establish the repeatable private-beta workflow:

- Deploy the existing dashboard on Vercel in the required SSO/proxy mode.
- Configure the browser-facing public URL and callback routes on the Vercel origin.
- Create the first beta organization manually.
- Configure its organization-specific identity provider.
- Verify owner login, logout, and expired-session behavior.
- Verify CLI or PAT access through the CloudFront API host if included in the beta.
- Write a concise onboarding checklist that another operator can follow.

**Gate:** An invited user can sign in without operator intervention after setup and cannot enter another organization's tenant context.

### M1.3 — Acceptance and operational handoff

Run the complete private-beta journey and produce operational evidence:

- Run the replay journey without a live model key.
- Run one user-triggered, tightly budgeted real-model journey if approved.
- Exercise governance pause and approval.
- Verify event streaming and resume behavior through the complete public route.
- Run positive and negative sandbox-network probes.
- Verify cross-tenant denial.
- Trigger and observe the relevant budget and operational alarms.
- Exercise manual run cancellation and tenant-containment procedures.
- Measure sandbox scale-down over an idle period.
- Reconcile modeled and measured infrastructure cost.
- Confirm the self-hosted chart and hermetic test suites remain unchanged and green.
- Publish the threat model, network documentation, operator runbook, and validation report.

**Gate:** Every hard acceptance criterion in Section 9 passes with recorded evidence.

## 7. Existing controls and known gaps

### Controls available in M1

- Per-tenant rolling LLM budget.
- Per-run monetary budget.
- Per-run wall-clock limit.
- Global sandbox ResourceQuota.
- Per-tenant egress-rate controls.
- Restricted private-beta membership.
- Operator cancellation through existing run APIs.
- AWS budgets, alarms, concurrency ceilings, and retention policies.

### Known gaps accepted for the private beta

- No atomic per-tenant concurrent-run claim.
- No calendar-month compute-credit enforcement.
- No reliable tenant suspend/reactivate lifecycle.
- Manual containment requires multiple operator actions.
- Cancelling current runs does not by itself create a durable tenant suspension.
- The single-node/RWO platform tier is not a high-availability production design.

These gaps must be visible in beta documentation. Budget alerts and a trusted cohort reduce exposure, but they are not substitutes for M3 admission enforcement.

## 8. Operator runbooks

M1 must document at least the following procedures:

- Provision a tenant.
- Configure or rotate an OIDC application.
- Configure or rotate model access.
- Verify the initial tenant owner.
- Inspect a failed or stuck run.
- Cancel an active run.
- Manually contain a tenant by deactivating access and cancelling active work.
- Respond to a Fluidbox-specific or account-wide budget alert.
- Rotate the CloudFront origin secret.
- Recover Core after a node or pod failure.
- Restore or validate database recovery.
- Scale or replace the system node.
- Tear down the environment and check for leaked resources.

The containment runbook must explicitly say that it is incomplete and may be awkward to reverse until Core gains a real suspend/reactivate capability.

## 9. Hard acceptance criteria

M1 is complete only when all of the following are demonstrated in the deployed AWS environment:

1. A scoped deployer can apply the infrastructure without using a root key.
2. Both Fluidbox-specific and account-wide budget controls are active.
3. An operator can manually provision an organization using documented steps.
4. An invited owner can log in through the Vercel origin.
5. The user can submit a replay run.
6. EKS creates an isolated sandbox for the run.
7. The run pauses for an approval and resumes after approval.
8. Events stream reliably through Vercel, CloudFront, and ALB, or the documented dedicated-stream fallback is proven.
9. Artifacts and usage are recorded by Core.
10. A sandbox cannot make disallowed network connections.
11. One tenant cannot read or mutate another tenant's resources.
12. Direct ALB requests are rejected.
13. Operator cancellation stops an active run.
14. The manual containment runbook has been exercised and its limitations recorded.
15. Sandbox node capacity returns to zero after the idle window.
16. Core, chart, and existing hermetic suites remain green without Core or chart modifications.
17. Measured idle cost is reconciled with the expected approximately **$130–140 per month** floor.
18. The threat model, network architecture, validation report, and operator runbooks are complete.

## 10. Definition of done

M1 is done when Fluidbox can invite and operate a small private-beta cohort without customers managing infrastructure and without changing the Core product.

Completion means the team has evidence—not merely a successful Terraform apply—that:

- customer login works;
- tenant isolation holds;
- governed runs complete;
- approvals work;
- network enforcement holds;
- long-lived event delivery works;
- spending is observable and bounded;
- idle sandbox cost returns to zero;
- an operator can provision, diagnose, cancel, contain, and recover the service.

Public signup must remain disabled after M1.

## 11. Cost expectation

The expected idle floor is approximately **$130–140 per month**, primarily from:

- EKS control plane: approximately $73;
- one small on-demand system node: approximately $24.50;
- ALB: approximately $16.50;
- public IPv4 addresses: approximately $11;
- EBS, KMS, logs, and CloudFront: approximately $5–15.

Sandbox compute should be zero while idle. The fixed cost is an intentional consequence of keeping the existing Kubernetes and Core primitives unchanged in M1.

## 12. Decisions required before execution

- Select the account-wide budget threshold.
- Confirm the AWS account and region.
- Approve the scoped IAM bootstrap.
- Confirm whether M1 identity uses manually configured WorkOS Connect or another supported OIDC provider.
- Create or link the Vercel dashboard project.
- Approve the first private-beta organization and owner.
- Approve any real-model acceptance run before model spending occurs.

## 13. Transition to M2

M2 should begin only after M1's operator workflow is stable and evidenced. M2 automates the manual steps that M1 proves:

- customer signup;
- organization creation;
- identity application provisioning;
- tenant provisioning and retry handling;
- organization discovery and management;
- hosted usage presentation.

This sequencing prevents Fluidbox from automating an operational process before the team has demonstrated that the underlying managed service is reliable.
