# fluidbox private beta — plan

**Candidate:** `0.4.0-rc.1` (release candidate, not published) on branch `release/prime-time-rc`.
**Status this plan is written against:** the overnight integration review verdict is **LIMITED BETA** — the two prior P0s are closed and re-verified, but several P1s remain open and some public claims still outrun the implementation (see [`../reviews/overnight-integration-review.md`](../reviews/overnight-integration-review.md) §9–§11). This beta is the instrument that turns that verdict into evidence for the next go/no-go. It is **not** a public launch.

This document is a plan. Every field marked `___` is measured later and must stay obviously unfilled until it is. Nothing here records an outcome that has happened.

---

## 1. Objective

Put the validated no-key first-run path and the honest security posture of `0.4.0-rc.1` in front of a small number of real external developers, on their own machines, and measure whether the onboarding and the core governed-run loop hold up **outside the single environment the maintainer has validated**.

Concretely, the beta exists to answer four questions with evidence rather than assertion:

1. **Does the onboarding path work for someone who is not the author**, on hardware and operating systems the maintainer has not tested (see §4 — only a macOS arm64 host running Linux arm64 containers has been validated)?
2. **Does the core governed-run loop deliver its promise** — a policy gate that decides before execution, an approval pause, a diff, and a cost line — reliably enough that a participant comes back for a second run and points it at a real repository?
3. **Are the security disclosures sufficient and honest** — can an operator understand, from the shipped documentation alone, that the Docker `HostDev` default is not an egress boundary and that the eval profile's API is network-reachable and protected only by its admin token?
4. **What breaks, for whom, and how often** — so that recurring failures, missing platform coverage, and new security findings surface here, privately, before any public launch.

## 2. What is being tested — and what is explicitly not

**In scope.**

- The documented onboarding path: `git clone` → `just demo` → first governed-run receipt, and the graduation paths from there (live Codex, live Claude, a real repository).
- The core governed-run loop: the permission gate, the human-approval pause, the diff artifact, and the cost report.
- Retention and depth: whether participants reach a real-repository run and return for a second run.
- The clarity and sufficiency of the security disclosures as written, judged by whether operators reach the right conclusions unaided.
- Optional: integration activation ergonomics (a GitHub App connection, a connector-catalog connection, a custom MCP server, or a trigger subscription).

**Explicitly out of scope.** These are not failures of the beta if they do not happen; asking for them would distort the signal.

- **Cloud scale and the load campaign.** The gated 60/150/300-concurrent-run exercises are tracked separately on issue #34 and are not part of this beta. No participant is asked to run at scale.
- **No paid cloud spend.** Kubernetes participants exercise the local kind + Calico path (`just k8s-dev`) or a cluster they already own and pay for; the beta never asks anyone to create paid cloud resources.
- **Live Claude enforcement as a validated claim.** The maintainer's Anthropic key is out of credit, so no live Claude run was exercised for this candidate (§4). The gate is proven without a model by `scripts/gate-proof.sh`; a participant with their own funded Anthropic key who does a live Claude run is exercising an **unvalidated** path, and that result is itself a finding.
- **Production use.** Disposable and test repositories only (§10).
- **Performance benchmarking, SLAs, or a supported-platform matrix.** Reports from amd64, Linux hosts, and Windows are welcome and valuable, but the beta does not certify them.
- **Closing the open P1s.** The known limitations in [`../../CHANGELOG.md`](../../CHANGELOG.md) (`0.4.0-rc.1` → "Known limitations in this candidate") and the open items in [`../launch/launch-blockers.md`](../launch/launch-blockers.md) are known going in. The beta runs alongside that work; it does not substitute for it.

## 3. Participants — 20 developers across four personas

Exactly **20 external developers**, five in each of four personas. Identities are recruited into the slots below; do not fabricate them, and do not over-recruit — a private beta's value is in close observation, not headcount.

| Slot | Persona | Name / handle | Platform (OS · arch · docker engine) | Contact | Status |
|---|---|---|---|---|---|
| P-01 | Platform / Kubernetes | `___` | `___` | `___` | `___` |
| P-02 | Platform / Kubernetes | `___` | `___` | `___` | `___` |
| P-03 | Platform / Kubernetes | `___` | `___` | `___` | `___` |
| P-04 | Platform / Kubernetes | `___` | `___` | `___` | `___` |
| P-05 | Platform / Kubernetes | `___` | `___` | `___` | `___` |
| P-06 | AI-agent builder | `___` | `___` | `___` | `___` |
| P-07 | AI-agent builder | `___` | `___` | `___` | `___` |
| P-08 | AI-agent builder | `___` | `___` | `___` | `___` |
| P-09 | AI-agent builder | `___` | `___` | `___` | `___` |
| P-10 | AI-agent builder | `___` | `___` | `___` | `___` |
| P-11 | Security engineer / reviewer | `___` | `___` | `___` | `___` |
| P-12 | Security engineer / reviewer | `___` | `___` | `___` | `___` |
| P-13 | Security engineer / reviewer | `___` | `___` | `___` | `___` |
| P-14 | Security engineer / reviewer | `___` | `___` | `___` | `___` |
| P-15 | Security engineer / reviewer | `___` | `___` | `___` | `___` |
| P-16 | General backend / OSS | `___` | `___` | `___` | `___` |
| P-17 | General backend / OSS | `___` | `___` | `___` | `___` |
| P-18 | General backend / OSS | `___` | `___` | `___` | `___` |
| P-19 | General backend / OSS | `___` | `___` | `___` | `___` |
| P-20 | General backend / OSS | `___` | `___` | `___` | `___` |

**Recruit deliberately for platform spread.** Only macOS arm64 has been validated (§4). The beta is far more valuable if the roster includes amd64 hosts, at least one Linux host, and — if anyone volunteers — Windows, precisely because those are unknowns.

### What each persona is uniquely placed to find

- **Platform / Kubernetes operators** exercise the Helm/OCI chart and the Kubernetes provider on the local kind + Calico path (`just k8s-dev`), or on a cluster they already run. They are uniquely placed to find defects in the `zeroEgress` sandbox namespace, the NetworkPolicy admission gate and its per-sandbox `netpol-gate` init container, per-run Pod/Secret lifecycle and teardown, and node sizing. They are also the readers most likely to catch the stale-EKS-framing disclosure being wrong or unclear.
- **AI-agent builders** already run coding agents, so they judge the governance model as practitioners: whether the policy gate is too permissive or too restrictive on real agent tooling, whether the Claude and Codex harnesses behave consistently, and whether the "attach does not mean allow" model and the approval flow are workable. They are the most likely to reach real-repository runs and second runs, and the most likely to notice the seed policy's treatment of the agent's tool vocabulary.
- **Security engineers / reviewers** test the boundary claims against reality. They run `scripts/gate-proof.sh` (no key, no model spend), read the threat model and the Security boundaries section, and probe the `HostDev` egress posture and the eval-profile network exposure. They are the participants most likely to file a security finding, and the ones whose "would you trust this" judgement matters most for a pre-1.0 security product.
- **General backend / OSS contributors** walk the from-source path (`just setup` → `just dev`, `just check`), judge whether the codebase and docs are approachable, and surface DX friction on the contribution path. They are the calibration group for onboarding: if the docs mislead a competent backend developer, they will mislead everyone.

## 4. Platform reality — what has actually been validated

State this plainly to every participant and record it in every observation (§ [`installation-observation.md`](./installation-observation.md)).

- **Validated for this candidate:** a **macOS arm64 host running Linux arm64 containers**. The keyless `just demo` path and `scripts/gate-proof.sh` both pass in that environment.
- **amd64 was not tested.** A participant on an Intel/amd64 host is exercising an untested architecture; their result is a finding either way.
- **A Linux host was not tested.** Only Linux *containers* on a macOS host were.
- **Windows was not tested.** Reports are welcome; support is not claimed.
- **No live Claude run was validated.** The available Anthropic key is out of credit (HTTP 400, confirmed directly and through the gateway).
- **A live Codex run was validated** (OpenAI, model `gpt-5.4-mini`, total cost **$0.0031 for two runs**).
- **The keyless deterministic demo (`just demo`) was validated** — `$0.00`, 0 model requests, 5 gate decisions.

## 5. The funnel and its definitions

Every stage is measured by facilitator observation plus participant self-report. fluidbox ships **no phone-home telemetry**; there are no server-side analytics to read. The only data are what the facilitator records (§ [`installation-observation.md`](./installation-observation.md)), a short structured check-in per participant, and the exit survey. The demo's own `.demo/receipt-*.json` files are non-sensitive (a fixture repo) and may be shared as corroborating evidence.

| Stage | Definition | Denominator | Result |
|---|---|---|---|
| **Install attempt** | The participant began the documented install: cloned the repo and started at least one of `just demo`, the Docker eval profile, or the from-source path. | 20 invited | `___` |
| **Stack ready** | The participant reached a running control plane: for `just demo`, the control plane reported healthy; for eval, the dashboard loaded at `localhost:3000`; for from-source, `just dev` came up. | install attempts | `___` |
| **First demo (time to)** | Wall-clock from the first `just demo` invocation to the first completed governed-run receipt (the 5 gate decisions printed). The one-time cold Rust compile and first image build are **included** and are the dominant variable — record whether the compile was cold or warm. | participants who reached a receipt | median `___` |
| **Governed-run completion** | Any governed run (demo or live) that reached terminal `completed` having produced gate decisions. | count across beta | `___` |
| **Real-repository run** | A governed run whose workspace was a participant's own real (non-fixture) repository. | count across beta | `___` |
| **Second run** | A participant returning to complete a second governed run in a separate sitting (a retention proxy). | distinct participants | `___` |
| **Integration activation** | A participant reached a connected state for at least one integration (GitHub App, connector-catalog connection, custom MCP server, or trigger subscription). Measured, not gated. | distinct participants | `___` |

Additional signals the beta must capture, all `___` until collected: **support required** (participants who needed facilitator intervention to pass a stage, and total intervention count/time), **recurring failures** (any failure mode seen in ≥2 participants, tracked in a running list), **security findings** (count and severity, routed privately per §9), **recommendation intent** (exit survey), and **contribution interest** (exit survey).

## 6. Pass thresholds

These are the success criteria for the beta as a whole. A `Met?` of `___` stays blank until the window closes.

| # | Threshold | Met? |
|---|---|---|
| 1 | At least **16 of 20** participants attempt installation | `___` |
| 2 | **80%** of attempts reach a running stack | `___` |
| 3 | **Median time to first demo under 10 minutes** | `___` |
| 4 | At least **10 governed-run completions** | `___` |
| 5 | At least **5 real-repository runs** | `___` |
| 6 | At least **5 second runs** (participants returning for a second run) | `___` |
| 7 | **No new P0** discovered | `___` |
| 8 | **No onboarding failure affecting more than 2 participants** | `___` |

Two of these carry known tension worth watching. Threshold 3 is at genuine risk because the keyless path compiles the control plane from source on first run (several minutes on a cold cache); the beta will quantify how often that pushes a first demo past ten minutes, which is itself a useful result. Threshold 4 is expected to be cleared by demo completions alone; the sharper signals of product value are thresholds 5 and 6.

## 7. Timeline — a two-week window, four phases

| Phase | Days | What happens |
|---|---|---|
| **Phase 0 — Preflight** | before Day 1 | Confirm the candidate SHA/tag; re-run `just demo` and `just gate-proof` on a clean machine; finalize the instruments in this directory; stand up the private disclosure channel; confirm the known-limitations list is shared. Invite nobody until this is green. |
| **Phase 1 — Canary** | Days 1–2 | A small canary cohort (2–4 participants, spread across personas and the most tolerant of rough edges) installs first, observed closely. This exists to protect threshold 8: a systemic onboarding break is caught here, before it reaches the other sixteen. |
| **Phase 2 — Main onboarding** | Days 3–7 | The remaining participants install, reach first demo, and complete a first governed run. Daily triage (§8). |
| **Phase 3 — Depth** | Days 8–12 | Real-repository runs, second runs, optional integration activation, and the security review pass. |
| **Phase 4 — Close-out** | Days 13–14 | Exit survey, final triage, funnel synthesis, and a written go/no-go recommendation for the next gate (RC → public launch). |

## 8. Findings triage

The maintainer triages. `.github/CODEOWNERS` names a single maintainer, and `SECURITY.md` commits to a 72-hour advisory acknowledgement; the beta is deliberately small so that commitment is honest under the added inbound volume (this capacity limit is itself a tracked risk — BLK-18).

- **Cadence.** Daily during Phases 1–2, then every two to three days through Phases 3–4.
- **Severity scheme** (from [`../launch/launch-blockers.md`](../launch/launch-blockers.md)): **P0** blocks launch — a public claim measurably false in a way a user relies on, or an unauthenticated/low-privilege attacker gaining code execution or data disclosure on a default path. **P1** blocks launch unless explicitly accepted in writing. **P2** ship-with-disclosure. **P3** track.
- **Routing.** Functional bugs and DX friction become GitHub issues. **Security findings never do** — they go through GitHub Security Advisories privately (§9). Each finding is logged with the participant slot, the funnel stage, the environment, and the verbatim error.

## 9. What halts the beta early

Pause and act — do not push through — on any of these:

- **A new P0.** Halt onboarding immediately. If it is a security P0, open a private advisory, coordinate disclosure (§ [`facilitator-guide.md`](./facilitator-guide.md)), fix, re-verify (including `just gate-proof`), and only then resume. Threshold 7 is failed for the beta the moment a new P0 is confirmed.
- **An onboarding failure affecting more than two participants.** This trips threshold 8. Pause the current wave, root-cause it, fix or document a workaround, and resume — this is exactly what the Phase 1 canary is designed to catch before it can reach a third person.
- **A participant exposing themselves.** If a participant is found running the eval profile on an untrusted network, or pointing a run at a sensitive repository, stop them, help them tear down, and treat it as a documentation/onboarding finding — the guidance was insufficient if this happened.

## 10. Scope boundaries

- **No paid cloud spend is asked of any participant.** Kubernetes work stays on local kind + Calico or a participant's existing cluster.
- **No production use.** Runs target disposable or throwaway repositories only.
- **No PII and no secrets.** Participants must not point a run at a repository containing personal data, credentials, or anything they would not paste into a public issue — reinforced by the two live-boundary facts below.
- **The Docker `HostDev` default is not an egress boundary.** The default sandbox network has general internet egress and the host's network position; only Kubernetes `zeroEgress` and Docker `Hardened` close it. Participants are told this in plain language.
- **The eval profile's API is network-reachable by necessity.** Its dashboard is loopback-only, but the API port is published on all interfaces because sandboxes reach the control plane over `host.docker.internal`; the required `FLUIDBOX_ADMIN_TOKEN` is the control protecting it, so it must run only on a trusted network.

## 11. Appendix — candidate known limitations

Reproduced in brief so no one has to hunt for them; the authority is [`../../CHANGELOG.md`](../../CHANGELOG.md) (`0.4.0-rc.1` → "Known limitations in this candidate") and [`../reviews/release-candidate-readiness.md`](../reviews/release-candidate-readiness.md).

- No live-model validation was possible (Anthropic key out of credit); the gate is proven without a model by `scripts/gate-proof.sh`, which is a stronger witness for the security property but is not a substitute for "a real model completes a real task."
- Nested sub-execution routing is untested, which is why the seed policy denies it.
- An older pinned `runner_image` on a newer server still routes nothing, and there is no server-side detection of a terminal run with a non-empty diff and zero `tool.decision` events.
- Supply chain unchanged: no lockfile for either runner image, `npm install` rather than `npm ci`, no Dependabot npm entry for the runner directories, and release artifacts are unsigned with no SBOM or attested provenance.
- The two earlier EKS acceptances predate the NetworkPolicy fix and have not been re-run against this candidate.
