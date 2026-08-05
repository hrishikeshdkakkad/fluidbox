# Fluidbox Cloud M1 — architecture & network

Status: M1 (managed private beta). Contract: zero core changes, zero chart
changes — everything below composes released artifacts. Parent: PLAN rev 3.

## Topology

```
invited user (browser)
    │  https
    ▼
Vercel (apps/web, sso mode)────────────────┐
    │  /v1/* rewrite + /api/fluidbox proxy │  CLI / PAT (bearer)
    ▼                                      ▼
CloudFront (default cert, no domain)  ◄────┘
    │  http :80 origin leg
    │  · origin SG: CloudFront origin-facing prefix list ONLY
    │  · rotating x-fluidbox-origin-auth header (ALB rule refuses without it)
    ▼
ALB (Ingress-created, target-type ip, idle 120s)
    │  /v1 + /.well-known + / → fluidbox-server:8787
    ▼
EKS "fluidbox-cloud" (1.35, us-east-1, subnets in 1b/1c, nodes pinned 1b)
 ├─ system nodegroup: 1× t4g.medium on-demand
 │    fluidbox-server (chart, unchanged) ── Neon Postgres (direct, RLS runtime role)
 │    litellm (composed Deployment, DB-backed) ── small Neon LiteLLM DB
 │    aws-lb-controller · cluster-autoscaler · CNI/CoreDNS/EBS-CSI/metrics/pod-identity
 └─ sandbox nodegroup: 0↔4 t4g.medium (tainted fluidbox.dev/sandbox)
      per-run sandbox pods (zeroEgress NetworkPolicy, netpol-gate init)
```

- **Identity to AWS:** operator user → scoped `fluidbox-cloud-deployer` role
  (root retired, M1.0). Workloads: EKS **Pod Identity** associations
  (server→KMS KEK, EBS CSI, ALB controller, autoscaler). Sandboxes have **no**
  association and their NetworkPolicy denies link-local anyway.
- **Custody:** `FLUIDBOX_KMS_MODE=aws` under `alias/fluidbox-cloud-kek`;
  losing the KEK is unrecoverable once v2 rows exist
  (`docs/hosted/kms-operations.md`). Operator secrets (admin token, credential
  key, LiteLLM master key, origin header) live in SSM SecureString
  `/fluidbox/cloud/*`, created out-of-band — never in Terraform state.
- **LLM path:** facade → composed LiteLLM (`FLUIDBOX_LLM_KEY_MODE=tenant`,
  per-tenant virtual keys, models allow-listed to haiku, $5/30d rolling
  tenant budget). The Anthropic key exists only in the LiteLLM pod's env.

## Network posture (and why there is no NAT)

Nodes sit in **public subnets with public IPs and no inbound** (SGs admit
nothing from the internet; the ALB reaches pods through the
controller-managed backend rules). Node egress (Neon, GHCR, Anthropic, SSM)
rides the IGW directly. A NAT gateway would add ~$32/mo + $0.045/GB against a
~$131/mo verified idle floor and would buy nothing for the actual security
boundary:

> **Sandbox pods are the untrusted plane, and their egress posture is
> enforced INSIDE the cluster** — the chart's zeroEgress NetworkPolicy
> (default-deny + control-plane-:8788-only), the boot-time enforcement probe,
> and the per-run netpol-gate init container that holds the runner until the
> pod's own policy is OBSERVED enforcing (AWS VPC CNI standard mode programs
> policy asynchronously; the gate contains that window). Node-level NAT was
> never that boundary.

EKS API endpoint: public access restricted to operator CIDRs + private access
for nodes. Control-plane logs on (30-day retention, adopted log group).

## The public edge lock (M1.1 gate: "direct ALB refused")

Two independent locks, because each covers the other's residual:

1. **SG lock** — the ALB's frontend SG admits :80 only from
   `com.amazonaws.global.cloudfront.origin-facing`. The internet cannot open a
   TCP connection to the ALB. Residual: *anyone's* CloudFront distribution
   can front our ALB.
2. **Origin header lock** — CloudFront injects `x-fluidbox-origin-auth`
   (secret value, SSM-held, script-rotated); an Ingress `conditions`
   annotation makes every ALB rule require it, so a foreign distribution gets
   the ALB default 404. Rotation: `scripts/cloud/rotate-origin-secret.sh`
   (overlap window: old+new accepted while CloudFront deploys).

TLS: viewers terminate on the CloudFront default cert (`*.cloudfront.net` —
M1 has no product domain). The CloudFront→ALB leg is **http-only by
construction** (an ALB cannot present a cert for its own
`*.elb.amazonaws.com` name): accepted for M1 because the leg rides AWS's
backbone between two AWS-operated endpoints and carries the two locks above;
recorded as a residual in the threat model. A product domain + ACM cert on
the ALB closes it in M2.

## Event streaming (SSE) — path, budgets, fallback

The dashboard's stream: browser → Vercel (`/api/fluidbox/[...path]` route
handler, which pipes `upstream.body` through untouched) → CloudFront → ALB →
`GET /v1/sessions/{id}/events/stream`.

Per-hop accounting for a quiet stream (server keepalive ≈ 15s):

| hop | knob | value |
|---|---|---|
| ALB | `idle_timeout.timeout_seconds` | 120s (chart values annotation) |
| CloudFront | `origin_read_timeout` (max quiet gap between bytes) | 60s |
| CloudFront | total duration | unlimited while bytes flow |
| Vercel route handler | function max duration | **MEASURED 2026-08-03: exactly 300s** on the live deployment (last tick 290s, next never arrived) |

Delivery is correct even when a hop caps the stream: **SSE fanout is hybrid
by design** — the `seq` catch-up query is the delivery source of truth and
`Last-Event-ID` resume reconnects exactly where the stream died (core
invariant, unchanged). A capped stream therefore degrades to a reconnect,
never to loss.

**Measured verdict (M1.0, 2026-08-03): Vercel CAN carry the streams, and the
fallback is NOT needed.** Against the live deployment
(`fluidbox-cloud-dashboard.vercel.app`, sso mode, real `/api/fluidbox` proxy):
first byte in 1s (unbuffered), continuous delivery to **exactly 300s**, then
the function is cut — and `Last-Event-ID` demonstrably reaches the origin, so
the browser's `EventSource` reconnects and resumes from the last `seq`. Because
core's SSE fanout is hybrid (the seq catch-up query is the delivery source of
truth, NOT the notify), a 5-minute reconnect costs a round-trip, never an
event. Evidence: `docs/reviews/2026-08-03-cloud-m1-readiness/` (`sse-stream-sample.txt`,
`sse-resume-sample.txt`, `cookie-proxy-headers.txt`).

**Retained fallback, should a future plan/runtime change shorten that window
to something users notice:** the dashboard opens its EventSource against the **CloudFront
API host directly** (`https://<cf-domain>/v1/sessions/{id}/events/stream`)
instead of the same-origin proxy path. PATs/bearer flows work today;
cookie-authenticated browser streams on a cross-origin host would need a CORS
allowance from core — which would be a core change, so under the M1 contract
the cookie-mode fallback is: shorter streams + aggressive `Last-Event-ID`
resume through Vercel (measured resume gap goes in the validation report),
with the CORS-based dedicated stream host recorded as an M2/M3 proposal.

## Hosts and the cookie origin (M1.2)

`FLUIDBOX_PUBLIC_URL` = **the Vercel origin** once the dashboard is live: the
per-org OIDC login dance rides the `/v1/*` rewrite so `__Host-fbx_web` lands
on the Vercel host, and cookie-authenticated writes enforce
`Origin == FLUIDBOX_PUBLIC_URL` exactly. Vercel env (mind the traps):

| var | value | trap |
|---|---|---|
| `FLUIDBOX_WEB_MODE` | `sso` | anything else throws at cold start |
| `FLUIDBOX_WEB_AUTH` | unset / `none` | `sso`+`workos` is REFUSED (two session systems) — the WorkOS web tier is the M2 dual-session design |
| `FLUIDBOX_API_URL` | `https://<cloudfront-domain>` | **read at BUILD time** by `next.config.ts` rewrites — set it before building; changing it means redeploy |
| `FLUIDBOX_PUBLIC_URL` (server side, helm) | `https://<vercel-origin>` | set in the M1.2 apply (`public_url` var) |

CLI/PAT traffic never touches Vercel: `https://<cloudfront-domain>` is the
API host (bearer auth, no cookies).

## Availability tier (declared, not apologized for)

Single system node, single server replica, node-local RWO archive PVC,
`Recreate` upgrades: **this is the declared beta tier** (PLAN rev 3). The
chart's one switch to grow out of it later is `server.archiveStore=s3`
(drops the PVC, enables RollingUpdate + replicas>1) — an M2+ decision.

## Cost

Idle floor re-verified 2026-08-03 at **≈ $130.6/mo** (in-band): see
`docs/hosted/cloud-cost-model.md` for line items, the light-use scenario, and
the levers. The two structural protections against version-drift cost: EKS
`upgrade_policy=STANDARD` (never ages into 6× extended-support billing) and
the no-NAT topology above.
