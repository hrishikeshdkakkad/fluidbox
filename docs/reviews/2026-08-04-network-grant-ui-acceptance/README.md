# Network-grant dashboard UI — live acceptance (2026-08-04)

**Verdict: PASS.** A run configured entirely through the new dashboard UI parked for
human authorization, was authorized with one click, received a frozen **public**
network grant enforced by the live Cilium datapath, and did real web research —
the exact workload whose every fetch died on DNS timeouts before this change.

This closes the criterion left open by the Cilium cutover
(`docs/reviews/2026-08-04-cilium-cutover/`): the owner-only last mile is gone —
egress is now grantable from the dashboard.

## What was live during the drill

| Artifact | Version | Proof |
|---|---|---|
| Dashboard | Vercel deploy `fluidbox-cloud-dashboard-q04wbb14x` (prod alias) | this drill ran on it |
| Control plane | `ghcr.io/hrishikeshdkakkad/fluidbox-server:0.6.0`, chart `0.6.0` | `kubectl get deploy` + boot log `sandbox network grants: enforcer 'cilium' (requested: cilium)` |
| Enforcer surfacing (Task 7) | live | `GET /v1/harnesses` through the dashboard proxy returned `{"network":{"enforcer":"cilium","supports_egress_grants":true}}` |

## The walk (all through the production UI, signed in as the Fluidzero owner)

1. **Governance → `init` → Where a sandbox may reach**: ceiling **Public** (the
   deny-wall caution renders), **Require a human to authorize each run** ticked,
   published as **v3** — the strict `deny_unknown_fields` draft parser accepted the
   payload on the first try (the 422 trap did not fire).
   *Note: the drill org's only policy is named `init`, not `default` — it is the
   org's de-facto default policy (governs its 1 agent).*
2. **Agents → `test` → Append revision 3**: the modal displayed
   "Governing policy ceiling: **Public**" (fetched live from the just-published v3),
   Network access mode set to **Public** (target list hidden with the
   core-refuses-that-pairing note), revision **3** saved and became current.
3. **New Run**: task "give me information about the GPU market using web research";
   composer section **5 · Network access** showed "Inherit from agent · Public" /
   "Offline only (this run)" with the narrow-never-widen note. Launched.
4. The run **parked in `awaiting_authorization`** — timeline row
   "network grant **public** · awaiting authorization" (that row IS
   `network.grant.frozen`; the renderer appends the suffix while parked) and the
   collapsed approval card showed exactly **Authorize** / **Deny** (no
   "Whole session" — the per-run collapse works).
5. **Authorize** clicked: `approved_once` by the owner → Allowed (human) →
   provisioning → initializing → running. The per-run CiliumNetworkPolicy was
   programmed and verified before the pod got its Secret:
   `kubectl get cnp -n fluidbox-sandboxes` → `fluidbox-019fcf55-… VALID=True` at 32s.
6. **Real research**: the codex agent fetched statista.com, newsroom.nvidia.com,
   idc.com, amd.com, intel.com, canalys.com, reuters.com, duckduckgo.com,
   wccftech.com, techpowerup.com, tomshardware.com — 15+ egress tool calls, every
   one "Allowed (policy)" — and reported mid-run: *"I've confirmed outbound access
   works."* No DNS timeouts anywhere in the timeline.
7. **Completed** with a sourced GPU-market summary (Jon Peddie Q3-2025 share data
   via Wccftech, Tom's Hardware pricing, TechPowerUp positioning). Cost **$0.0180**,
   6 model calls. Terminal row: "network grant revoked · run terminal"; server log:
   `network grant revoked (run terminal) session_id=019fcf55-… mode=public`.

## Evidence

- `network-grant-ui-acceptance.gif` — the full recorded flow (sign-in → Governance
  publish → revision → composer → parked run → Authorize → live research).
- `01-timeline-grant-frozen-authorized.jpg` — completed run header: frozen public
  grant, `approved_once`, Allowed (human), provisioning→running, first fetches.
- `02-live-web-research-allowed.jpg` — the research mid-section: "I've confirmed
  outbound access works", curl calls, per-call Allowed (policy).
- `03-completed-result-grant-revoked.jpg` — the agent's final market summary,
  → completed, "network grant revoked · run terminal".
- `timeline.md` — the full timeline text as rendered, plus the verbatim result.

Run: session `019fcf55-fd86-7d33-8159-dc76ccaf45e0`, agent `test` rev 3
(codex, gpt-5.4-mini), policy `init` v3, org `fluidzero`.

## Honest notes

- **Automation disclosure.** The acceptance was driven in the owner's real Chrome
  session. The run-detail page loads its data exclusively through a
  visibility-gated poller (`useSmartPolling`) + SSE-triggered refreshes; the
  automation window was OS-occluded (`document.visibilityState === "hidden"`), so
  the page sat on its skeleton. To proceed, the visibility getter was shimmed to
  `"visible"` in that tab — after which the page ran its own normal code path
  (real fetches, real render), and the Authorize click was a genuine UI click.
  Every state change (publish, revision, launch, authorize) hit the production API
  unassisted.
- **Follow-up (pre-existing, surfaced by the above):** the session page performs no
  unconditional initial `loadMeta()` — a hidden/occluded tab renders the skeleton
  forever even though every API call succeeds. Worth a one-line mount fetch.
- A neighbouring run "Figure out the latest news in the GPU chip industry"
  (schedule, 8 minutes before this drill) shows **failed** in Run history — it
  predates this drill's policy/declaration work and is not part of this
  acceptance.
