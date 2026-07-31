# fluidbox private beta — metrics scorecard

This is the manual instrument that turns 20 participants' returns into a single pass/fail
verdict. It is deliberately reproducible: two people scoring the same set of returns must
reach the same numbers. There is **no automatic telemetry** behind any of this — every
value is transcribed by hand from the feedback questionnaire (`feedback-form.md`) and from
any private security reports. If it isn't in a participant's return, it is not counted.

The panel is exactly 20 participants: four personas of five each — platform/Kubernetes
engineers, AI-agent builders, security engineers, and general backend/OSS developers.

---

## How to score a metric you could not measure

Some cells will be unknown: a participant did not time the demo, skipped a section, or
withdrew. **Record the unknown as `—` (unmeasured), never as `0` and never as a guess.**
The rules that follow from that:

- An unmeasured value is **excluded from the denominator** of any rate or median, and the
  `n` actually used is reported next to the result.
- An unmeasured value is **never counted as a success**. "Did not report a governed run"
  is not the same as "completed a governed run", but it is also not evidence of failure.
- Every `—` gets a one-line reason in the participant's Notes cell (e.g. "withdrew after
  install", "did not time demo"). Do not impute a plausible number to fill a gap; a
  fabricated value is worse than a missing one because it silently moves a threshold.

---

## Metric definitions (the exact rules two scorers must share)

Ambiguity is the enemy of a reproducible scorecard, so each metric below states precisely
what counts.

**Install attempt.** A participant *attempted installation* if they ran the first
documented command of any install path (the `git clone` of the keyless demo path, the
`docker compose ... pull` of the eval path, `just setup` of the from-source path, or a
Helm install), regardless of whether it succeeded. Unit: distinct participants. A
participant who only read the README without running a command did **not** attempt.

**Stack-ready.** A participant reached a *running stack* if their control plane answered
`/v1/health` and they were able to create at least one run — evidenced by the demo
printing state transitions, the eval dashboard loading a run, or a run appearing via CLI.
Reaching a compiled binary, or a container that started but never served health, is **not**
stack-ready. Unit: distinct participants. Only participants who attempted can be
stack-ready.

**Time to first demo.** Wall-clock minutes from the participant's first command of their
chosen demo path to the moment they first see a completed governed-run receipt (the demo's
diff + cost + security receipt, or the dashboard showing a finished run). The clock
**includes first-run source compilation** for the keyless path, because that latency is
part of the real first-run experience; it **excludes** the time to install Docker itself
and to `git clone` (network-bound, not fluidbox's onboarding). Self-reported in whole
minutes; if the participant did not time it, the value is `—`. If the median lands above
the threshold, record the dominant cause per participant (compile vs. image pull vs.
debugging a failure) — that distinction is the actionable finding.

**Governed-run completion.** A run that (a) reached terminal state `completed` and (b) has
at least one server-authored `tool.decision` in its ledger — i.e. the gate actually
decided at least one tool call. The keyless demo, run to its receipt with a non-zero
decision count, counts. A run that ended before the agent started (zero gate decisions),
or that "succeeded" against an empty workspace, does **not** count. Unit: total count of
such runs across all participants.

**Real-repository run.** A governed run (as above) whose workspace was a repository the
participant supplied, not the shipped `scripts/demo-fixture`. Unit: total count of such
runs across all participants. A real-repository run that produced an empty/zero-byte diff
is a red flag (see failure mode 1 in the troubleshooting guide) and is recorded but **not**
counted as a real-repository run, because an empty workspace means nothing actually ran.

**Second run.** A participant who created two or more governed runs (their first, then at
least one more). Unit: distinct participants with `governed runs completed ≥ 2`. This is
the return-intent signal; it counts people, not runs.

**Integration activation.** A participant who activated at least one integration (GitHub
App, an OAuth or API-key connection, a custom MCP server, or a trigger/schedule) and had
it work at least partly. Unit: distinct participants.

**Recurring failure.** Any single failure mode (from the troubleshooting guide's
enumerated list, plus "other") counted by the number of **distinct participants** it
affected. This column is what the "no onboarding failure affecting more than 2
participants" threshold reads from.

**Support required.** A participant who needed a direct maintainer response (beyond the
docs) to reach a running stack or a governed run. Unit: distinct participants. Not a pass
threshold, but a health signal.

**Security finding.** A privately-disclosed report, triaged to a severity (P0–P3) per the
troubleshooting guide's escalation rules. Counted separately from the questionnaire — a
security finding never arrives through this form. The "no new P0" threshold reads from the
P0 count.

**Recommendation intent.** The 0–10 score from section 9 of the form. Reported as the
distribution and the count of scores ≥ 9; not a pass/fail threshold, but a headline
outcome.

**Contribution interest.** A participant who answered "maybe" or "yes" to contributing.
Unit: distinct participants; a health signal, not a threshold.

---

## Per-participant tally

One row per participant. Fill from their return. Persona is the assigned bucket
(K = platform/Kubernetes, A = AI-agent builder, S = security engineer, B = general
backend/OSS). Every measured cell starts blank; use `—` for unmeasured with a Notes reason.

| ID | Persona | Attempted (Y/N) | Stack-ready (Y/N) | First-demo mins | Governed runs (n) | Real-repo runs (n) | Second run (Y/N) | Integration (Y/N) | Rec. score (0–10) | Support needed (Y/N) | Sec. findings (n) | Contribute (N/maybe/Y) | Notes |
|----|---------|-----------------|-------------------|-----------------|-------------------|--------------------|------------------|-------------------|-------------------|----------------------|-------------------|------------------------|-------|
| P01 | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ |
| P02 | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ |
| P03 | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ |
| P04 | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ |
| P05 | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ |
| P06 | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ |
| P07 | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ |
| P08 | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ |
| P09 | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ |
| P10 | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ |
| P11 | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ |
| P12 | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ |
| P13 | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ |
| P14 | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ |
| P15 | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ |
| P16 | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ |
| P17 | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ |
| P18 | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ |
| P19 | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ |
| P20 | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ |

Column totals (transcribe before computing the rollup):

- A = participants with Attempted = Y: `___`
- R = participants with Stack-ready = Y: `___`
- Governed-run count (sum of the Governed runs column): `___`
- Real-repo-run count (sum of the Real-repo runs column): `___`
- Second-run participants (count of Second run = Y): `___`
- First-demo times recorded (list the numeric values, ignoring `—`): `___`

---

## Recurring-failure tally

One row per enumerated failure mode; count the **distinct participants** who reported it in
section 7 of the form. The right-hand column is the threshold check: three or more
participants on any single onboarding failure is a breach of "no onboarding failure
affecting more than 2 participants".

| Failure mode | Participants affected | ≤ 2 OK / ≥ 3 BREACH |
|--------------|-----------------------|---------------------|
| Docker could not share the checkout / empty workspace / empty diff | ___ | ___ |
| "No such image" after preflight passed (context vs `DOCKER_HOST`) | ___ | ___ |
| First run looked hung while compiling from source | ___ | ___ |
| Port already in use (19790/19791/15434 or 8787/3000) | ___ | ___ |
| Post-upgrade: every supervised run pauses on ordinary tooling | ___ | ___ |
| Control plane never became healthy (demo timed out) | ___ | ___ |
| Missing Docker / Docker not running | ___ | ___ |
| Missing or rejected credential (admin token, model key) | ___ | ___ |
| Leftover containers / volumes / ports after teardown | ___ | ___ |
| Other (describe) | ___ | ___ |

Highest single-mode participant count: `___`  → threshold satisfied only if this is `≤ 2`.

---

## Rollup — each threshold, with the arithmetic

Fill each computed value from the totals above. The arithmetic is written out so an
independent scorer reproduces the same result.

**1. Install attempts ≥ 16 of 20.**
Count `A` = participants with Attempted = Y. Pass if `A ≥ 16`.
`A = ___`  → **PASS / FAIL: ___**

**2. Stack-ready rate ≥ 80% of attempts.**
Rate = `R ÷ A × 100`, where `R` = stack-ready participants and `A` = attempting
participants (the denominator is attempts, **not** all 20, so a non-attempter neither helps
nor hurts). Round to one decimal. Pass if `≥ 80.0%`.
`R = ___`, `A = ___`  →  `R ÷ A × 100 = ___%`  → **PASS / FAIL: ___**

**3. Median time to first demo < 10 minutes.**
Take every recorded first-demo time (exclude `—`). Sort ascending. The median is the
middle value if the count `n` is odd, or the mean of the two middle values if `n` is even.
Report `n`. Pass if the median is `< 10.0` minutes.
Sorted values = `___`  ; `n = ___`  ; median = `___` min  → **PASS / FAIL: ___**

**4. Governed-run completions ≥ 10.**
Sum the Governed runs column. Pass if the total `≥ 10`.
Total = `___`  → **PASS / FAIL: ___**

**5. Real-repository runs ≥ 5.**
Sum the Real-repo runs column (empty-diff runs excluded per the definition). Pass if `≥ 5`.
Total = `___`  → **PASS / FAIL: ___**

**6. Second runs ≥ 5.**
Count participants with Second run = Y. Pass if `≥ 5`.
Count = `___`  → **PASS / FAIL: ___**

**7. No new P0.**
From the security-findings triage, count confirmed P0 findings newly attributable to this
candidate. Pass if the count is exactly `0`.
P0 count = `___`  → **PASS / FAIL: ___**

**8. No onboarding failure affecting more than 2 participants.**
Take the highest single-mode participant count from the recurring-failure tally. Pass if
that maximum is `≤ 2`.
Max = `___`  → **PASS / FAIL: ___**

---

## Verdict

The beta **PASSES overall only if all eight thresholds pass.** Any single FAIL makes the
overall verdict FAIL, and the failing thresholds are named explicitly — a partial pass is
still a fail, stated honestly.

- Threshold 1 (install attempts ≥ 16): `___`
- Threshold 2 (stack-ready ≥ 80%): `___`
- Threshold 3 (median first demo < 10 min): `___`
- Threshold 4 (governed runs ≥ 10): `___`
- Threshold 5 (real-repo runs ≥ 5): `___`
- Threshold 6 (second runs ≥ 5): `___`
- Threshold 7 (no new P0): `___`
- Threshold 8 (no onboarding failure > 2 participants): `___`

**Overall verdict: `___` (PASS / FAIL)**

Failing thresholds, if any: `___`

Scored by: `___`  Date: `___`
Independently re-scored by: `___`  Date: `___`  Agreed? `[ ] yes  [ ] no — reconcile`

---

## Non-threshold outcomes (record, do not gate on)

These are read alongside the verdict; they explain *why* the numbers came out as they did.

- Recommendation-intent distribution (list the 0–10 scores): `___`  ; count ≥ 9: `___`
- Integration activation (participants): `___` of 20
- Support required (participants): `___` of 20
- Contribution interest (maybe or yes): `___` of 20
- Per-persona funnel note — did any one of the four personas fail to reach a governed run
  while others succeeded? `___`
- Security findings by severity (P0/P1/P2/P3): `___ / ___ / ___ / ___`
