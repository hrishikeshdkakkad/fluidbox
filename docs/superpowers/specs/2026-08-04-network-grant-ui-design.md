# Governed sandbox egress, selectable in the dashboard — design

**Date:** 2026-08-04 · **Branch:** `feat/cloud-m1` (single trip to prod) ·
**Status:** design, approved to spec

## Goal

Make the three sandbox network grant modes — `offline`, `approved`, `public` —
configurable from the dashboard, so an owner can grant an agent egress without
touching curl or YAML, and so the GPU-research agent can actually do research.

## What already exists

The backend is complete and running in production (v0.5.1, Cilium enforcer
resolved — see `docs/reviews/2026-08-04-cilium-cutover/`). Specifically:

- `POST /v1/policies` content accepts a `network` section (the **ceiling**).
- `POST /v1/agents` and `/v1/agents/{id}/revisions` accept `network` (the
  **declaration**). An absent field carries the previous revision's value
  forward, so an unrelated edit cannot wipe a declaration.
- `POST /v1/sessions` accepts `network` (the per-run **override**, narrowing
  only).
- A parked grant rides the ordinary approvals machinery — synthetic identity
  `tool = "network.grant"`, `tool_call_id = "network-grant"` — so idempotency
  and expiry come free, and the existing inline approve/deny UI already reaches
  it.
- The session timeline already renders `network.grant.frozen`,
  `network.denied`, and `network.denied.rollup`.

**No new backend *behaviour* is required** — nothing about how grants resolve,
freeze, or enforce changes. One small read-only field is added so the dashboard
can see what the deployment can enforce; that is the entire server-side scope.

## Decisions taken

| Question | Decision |
|---|---|
| Which surfaces get editing UI | **All three** — policy ceiling, agent declaration, per-run override. A composer picker alone would be inert, exactly like today's greyed-out "Free rein". |
| How to treat `public` | **Ship it, with an inline caution** naming the deny-wall residual. The serious paths are already covered by the ALB's origin-auth header and by sandbox tokens being audience-scoped to `/internal`. |
| What the GPU agent runs as | **`public` + `require_approval`.** Open-ended research cannot enumerate its domains in advance; the human pause is the real control, not a domain list nobody can predict. |
| Where egress lives in the run composer | **Its own control**, beside Guardrails — not folded into the preset cards. Guardrails answers "what may it do", Network answers "where may it reach". |
| Enforcer visibility | **Add it.** Worth breaking the zero-backend-change property (see below). |

## Architecture

Everything lands on `feat/cloud-m1`, which now contains `origin/main` (merged
clean, no conflicts). The branch is a true superset: production's exact core,
the Cilium/cloud kit, and this UI in one history. That is what makes "one trip
to prod" literal — and it was not optional, because the pre-merge branch lacked
`max_grant_secs` and 482 lines of the two files this UI mirrors.

The browser never decides what a policy *means*. Target validation rides the
existing `POST /v1/policies/validate` and `/policies/preview`, as every other
section of the editor already does. No client-side policy logic — the
presentation-only constraint holds.

**Shipping is a two-artifact chain, and the enforcer field is what makes it
two.** Be explicit about this, because "one trip to prod" is easy to
misread:

1. The dashboard ships by `vercel deploy --prod` (CLI only — no Git
   integration, so `git push` alone changes nothing in production).
2. The `network` field on `/v1/harnesses` is Rust, so it needs a **release**
   — merge to main, let release-please cut 0.5.2, wait for the image, then
   bump `chart_version` and `terraform apply` the app stack.

The UI can ship first and degrade gracefully: absent the field, treat the
enforcer as unknown and render the ceiling selector enabled with no banner —
i.e. exactly today's behaviour. That keeps the two artifacts independent
instead of forcing a lockstep deploy.

## The one backend addition

`GET /v1/harnesses` — already the dashboard's authenticated source of truth for
what this deployment supports — gains a sibling object:

```json
{ "harnesses": [...],
  "network": { "enforcer": "cilium", "supports_egress_grants": true } }
```

**Why it earns its keep.** Without it the dashboard would happily offer a
ceiling the deployment cannot enforce, and the operator would discover this
only when a run is refused at creation. That is precisely the bug class that
cost a day on 2026-08-04: `FLUIDBOX_NETWORK_ENFORCER=cilium` was parsed,
validated, logged — and never reached the constructor, so a correctly-configured
cluster silently had no enforcer. The rule that saved us was *report what
resolved, not what was requested*, and this field extends that rule to the UI.

The value must come from `provider.network_enforcer()` — asking the provider,
never echoing config. When `supports_egress_grants` is false, the ceiling
selector renders disabled with the reason stated.

Accepted trade: the route's name becomes slightly broader than its contents
suggest. A new `/v1/deployment` route would read better and cost an extra round
trip plus more surface; not worth it.

## Components

**1. `PolicyContent.network`** (`apps/web/app/lib/api.ts`) — TypeScript only.
Verified the runtime path already round-trips: the editor deep-clones the
server's content into its draft and publishes the whole object, and
`PolicyLimits` patches by spread. `network` survives a UI edit **today**,
unmodelled. This type is additive, not a rescue.

**2. `NetworkSection`** — Governance, alongside Budgets and Approvals. Ceiling
radio, allowed-target list, `require_approval`, `max_grant_secs`. The `public`
option carries the caution.

**3. `TargetRuleEditor`** — shared row editor for `TargetRule` (kind,
exact-or-wildcard pattern, port range, protocol), used by both Governance and
the agent editor. **The wildcard control must state that `*.nvidia.com` does
not match the bare apex.** That is a Cilium `matchPattern` fact — its `*`
cannot cross a dot — and it is the single most likely misconfiguration. The
type models it honestly; the UI must too.

**4. Agent editor** — a Network access block: mode plus targets, reusing
`TargetRuleEditor`. Under `public` the target list is hidden, because core
refuses that pairing as a false narrowing. **It also displays the governing
policy's ceiling inline** (see failure modes).

**5. Run composer** — a "Network access" block beside Guardrails: *Inherit from
agent* or *Offline only*. Overrides narrow only. Per-target narrowing is
expressible in the API and deliberately not built — fiddly UI, rare case.

**6. Approval card** — when the pending approval's tool is `network.grant`,
render mode, targets and lifetime, and collapse the buttons to a single
**Authorize** plus Deny. "Approve once / Approve for session" is meaningless
for a grant that is inherently per-run. Presentation only: the decision value
sent stays `approved_once`.

## Data flow

Governance edits follow the established path: deep-clone server content into a
draft, preview on change so the server resolves meaning, publish with
`base_version` so a moved head is a 409 rather than a silent overwrite.

Agent edits append a revision (agents are append-only). The UI sends `network`
only when the user changes it.

At run time the chain resolves server-side: declaration → narrowed by any
override → checked against the ceiling → frozen into the RunSpec, or parked.
With `require_approval`, the run enters `awaiting_authorization` and a pending
approval appears; authorizing releases it. The enforcer then programs the
per-run policy and **verifies it before the pod receives its Secret**, so the
sandbox cannot begin work outside its cage.

## Failure modes

**Ceiling/declaration mismatch is the one that matters.** An agent declaring
`public` under a policy capped at `approved` fails at run creation — after the
user has saved and launched. The agent editor therefore fetches and displays
the governing policy's ceiling inline, so the conflict is visible where it is
authored rather than where it detonates.

The rest are cheaper: `public` + targets is refused by core (the UI hides the
list, but the server refusal is the real guard); the wildcard-apex trap gets an
inline hint; nested typos already refuse via `DraftNetwork`'s
`deny_unknown_fields`; and a deployment without an enforcer now says so up
front rather than at create time.

## Acceptance

CI already builds the web app. The real proof is end to end on the live
deployment, and it closes the criterion left open on 2026-08-04:

1. Set the drill org's policy ceiling to `public` with `require_approval`,
   through the new Governance section.
2. Declare `public` on the `test` agent through the agent editor.
3. Launch the GPU-research agent.
4. Authorize the parked grant from the session timeline.
5. Observe `network.grant.frozen` with `mode: public`, the agent reaching the
   internet, and the run returning real research.

Evidence lands in `docs/reviews/<date>-network-grant-ui-acceptance/`.

## Out of scope

Per-target narrowing in the run composer; a bulk/paste target importer; Hubble
flow observation (`netobserve` has logic but no producer); and the eight live
traffic/bypass assertions in the EKS acceptance runbook, which remain
unexecuted and are not claimed by this work.

## Residuals

`public` mode on this deployment carries the documented deny-wall residual:
`deploymentPublicCIDRs` lists the ALB's current public IPs, which AWS
reassigns, and cannot enumerate CloudFront. Mitigated by the ALB's rotating
origin-auth header and by sandbox tokens being audience-scoped to `/internal`.
Recorded in `docs/reviews/2026-08-04-cilium-cutover/`, and surfaced to the
operator by the UI caution rather than left in a document nobody reads.
