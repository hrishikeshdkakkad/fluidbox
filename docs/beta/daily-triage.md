# fluidbox private beta — daily triage

The beta is small (20 participants, one maintainer), so triage is a short, repeatable
morning loop rather than a process. Its job is to catch two things early: a security report
that must be acknowledged inside the security window, and an onboarding failure that is
quietly climbing toward a threshold breach. Everything else can wait for the queue.

## Every morning, in this order

Security first, because it has a clock; then the funnel; then fixes.

1. **Check the private disclosure inbox.** GitHub Security Advisories and the
   `[fluidbox security]` mailbox. Any new report is acknowledged within 72 hours and
   assessed within a week (`SECURITY.md`). A confirmed P0 changes the day — see *Halting*.
2. **Read new questionnaire returns and the beta feedback channel.** Anything overnight.
3. **Transcribe new returns into the metrics scorecard** and **recompute the rollups.** Do
   not eyeball it — recompute, so a threshold that just slipped is seen the day it slips.
4. **Update the recurring-failure tally.** For each failure a return reported, increment the
   count of distinct participants for that mode. Watch the numbers approaching 2 and 3.
5. **Check CI on any same-day fix branch.** The gated checks (Rust suite, dashboard build,
   `cargo-deny`, `gate-proof.sh`, the compose and version guards) must be green before a fix
   is considered done.
6. **Run the halt check** (below), then **write the daily log row.**

## Classifying what came in overnight

For each new item — a return, a bug report, or a security report — answer three questions.

**How severe is it?** Use the severity levels from the troubleshooting guide: S0 (security
or a broken guarantee), S1 (onboarding blocker), S2 (bug with a workaround), S3 (cosmetic /
docs). A security report is S0 by default until assessed otherwise.

**Is it new?** Match it against the known failure modes and against issues already logged.
A duplicate of a known mode is *not* a new problem — but it **is** another participant on
that mode's counter, which may matter more than novelty (see the third question). A genuinely
new failure gets its own line in the log and, if it is an onboarding failure, its own row in
the recurring-failure tally.

**How many distinct participants does it now affect?** This is the threshold-linked
question. The pass bar includes "no onboarding failure affecting more than 2 participants",
so the count of distinct participants on any one onboarding failure mode is a live threshold
gauge, not a curiosity.

## The rule that turns a watch item into a breach

**A recurring onboarding failure that reaches a third participant is escalated
immediately, because it breaches a stated pass threshold.** One participant on a mode is a
data point; two is a watch item; **the third occurrence converts it into a threshold breach**
of "no onboarding failure affecting more than 2 participants". At the third participant, the
mode moves to same-day handling and the overall beta verdict is flagged at-risk until the
mode is fixed or the affected participants are unblocked with a durable workaround that is
then folded into the docs.

## Same-day versus queued

**Fix or act on the same day:**

- Any S0 (security) — acknowledge privately at once and begin assessment inside the window.
- Any S1 onboarding blocker with no workaround.
- Any onboarding failure that just crossed the third-participant line (per the rule above).
- Any regression that turned a gated CI check red.

**Queue (batch into the roadmap, do not interrupt the day):**

- S2 bugs that have a working documented workaround.
- S3 cosmetic and documentation items.
- Feature requests and "would be nice" integration asks.

A queued item still gets logged, so it is not lost; it just does not preempt the day.

## Deciding the beta must be halted

Halting means: stop inviting and onboarding new participants, tell the active participants
plainly what happened, fix it, then resume. Halt when any of these is true:

- **A new P0 is confirmed** (a gate/containment bypass, a credential or prompt exposure, an
  approval forge, a budget bypass) **and there is no same-day mitigation.** This also
  breaches the "no new P0" threshold outright.
- **An onboarding failure affects more than 2 participants** and there is no same-day fix
  and no durable workaround — the stated threshold is already breached and every new
  participant would walk into the same wall.
- **The software is shown to have exposed participant data** (which is also an S0).
- **The security response window cannot be honored** — for example the maintainer is
  unavailable for long enough that a 72-hour acknowledgement is at risk. Pause intake rather
  than let a report sit; an unacknowledged security report is worse than a paused beta.

Halting is reversible and cheap for a 20-person beta; treat it as a normal tool, not a
last resort. Resume once the trigger is fixed and re-verified, and note the halt and the
resume in the log.

## Standing agenda (same six items, same order, daily)

1. Security inbox — acknowledge (≤ 72h) and assess (≤ 1 week) anything new.
2. New returns → scorecard → recompute rollups.
3. Recurring-failure tally — any mode at 2 is a watch; any mode at 3 is a breach, escalate.
4. Same-day queue — fix and verify against green gated CI.
5. Halt check — is any halt trigger met?
6. Log the day.

## Daily log

One row per day of the beta. Keep it terse; it is a ledger, not a report.

| Date | Security items (new / ack'd / assessed) | New returns | New issues (severity · #participants · new?) | Threshold status (which of the 8 are OK / at-risk / breached) | Same-day actions taken | Halt decision | Notes |
|------|------------------------------------------|-------------|----------------------------------------------|---------------------------------------------------------------|------------------------|---------------|-------|
| ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ |
| ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ |
| ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ |
| ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ |
| ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ |
| ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ |
| ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ |
| ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ |
| ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ |
| ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ |
| ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ |
| ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ |
| ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ |
| ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___ |

Threshold-status shorthand for the fifth column: T1 install attempts, T2 stack-ready rate,
T3 median time to first demo, T4 governed runs, T5 real-repo runs, T6 second runs, T7 no new
P0, T8 no onboarding failure > 2 participants. Mark each OK, at-risk, or breached so the
verdict is never a surprise on the last day.
