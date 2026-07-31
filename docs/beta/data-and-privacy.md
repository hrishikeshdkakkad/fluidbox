# fluidbox private beta — data and privacy

Privacy is a constraint on this beta, not a paragraph in it. fluidbox governs AI agents
that touch people's code; a beta that quietly hoovered up prompts, repositories, or
credentials would contradict the product's own premise. So the design goal here is to make
the onboarding funnel measurable **without collecting any of that**, and the answer is a
manual, self-reported scorecard with no automatic collection at all.

## The default: manual and self-reported, with no automatic collection

The single most important fact: **the fluidbox software does not phone home, and the beta
adds no instrumentation to it.** There is no analytics SDK, no usage beacon, no crash
reporter, no "improve the product" toggle that ships data anywhere. The append-only event
ledger a run produces lives only in the participant's own database and on their own disk.
Every number in the metrics scorecard comes from a participant choosing to type an answer
into the feedback questionnaire. If a participant returns nothing, we have nothing — and
that is by design.

## What is collected

Only what a participant deliberately puts in a return:

- Their pseudonymous participant ID (P01–P20).
- Their environment, at the coarsest useful grain: operating system, CPU architecture,
  container engine, and which install path they chose.
- Their closed answers (yes/no, counts, the 0–10 recommendation score) and their open-text
  answers, from the feedback questionnaire.
- The metrics derived from those answers (the scorecard tallies).
- Separately, and only if they choose to file one: a private security report.

Held apart from all of the above, in a different place, is the identity mapping — a
participant's real name and contact detail against their participant ID — used solely to
invite them and to reach them. It is never merged into the analysed dataset.

## What is explicitly never collected

Not by the software, and not requested in any form:

- Prompts or task text sent to a model.
- Model output.
- Repository contents or source code, in whole or in fragment.
- File paths from a private repository.
- API keys, session tokens, PATs, the `.demo/` admin token, `.env` contents, or any other
  secret.
- Run receipts, diffs, or artifacts from a run against a participant's own repository.
- IP addresses, device identifiers, or any passive network/telemetry signal.
- A participant's real name or employer *inside* the analysed answers (identity is held
  separately, as above).

The questionnaire is written so that no question can be answered only by revealing one of
these. Where a participant might be tempted to paste evidence — for example an empty-diff
run — the form asks for a description, not the artifact. Participants are told, in the form
and in the consent notice, never to paste code, paths, secrets, or private-repo receipts.

## Legal and ethical basis: consent

fluidbox is an MIT-licensed open-source project run by a single maintainer. There is no
employment relationship, no contract, and no legitimate-interest claim over a participant's
data. The only basis for holding anything is the participant's **freely given, specific,
informed, and revocable consent**, obtained before they join and recorded against their
participant ID. Participation is voluntary; declining, or withdrawing later, carries no
penalty and affects nothing else about their use of the open-source project.

## Retention and deletion

- Raw questionnaire returns are kept for the duration of the beta plus **90 days** after it
  formally closes, to allow the scorecard to be computed, re-scored independently, and
  written up. After that window they are deleted, and only the non-attributed aggregate
  numbers and paraphrased themes survive.
- The identity mapping (name/contact ↔ participant ID) is deleted at beta close, or sooner
  on request, unless the participant has explicitly asked to be contacted about a specific
  follow-up (e.g. a contribution).
- A private security report follows the project's security process, not this retention
  window: it is kept as long as needed to ship and credit a fix, per `SECURITY.md`.
- A participant may request earlier deletion at any time (see *Withdrawal*), and that
  request always wins over the default window.

## Who can see what

- Raw returns and open-text answers: the maintainer only. fluidbox is pre-1.0 with a single
  maintainer (`SECURITY.md`), so "the team" is one person; there is no wider distribution.
- Open-text answers occasionally contain something identifying that a participant included
  by accident. The maintainer redacts such detail before any answer is quoted or shared,
  even internally in notes meant to outlive the beta.
- Aggregate results — the scorecard rollups and verdict, pooled and non-attributed — may be
  shared publicly (a launch write-up, a roadmap note). No per-participant row, score, or
  quote is published with an attributable identity without that participant's separate,
  explicit permission.
- A private security report is seen only by the maintainer and anyone the reporter and
  maintainer jointly agree to involve in the fix.

## A security finding is handled differently from ordinary feedback

Ordinary feedback rides the questionnaire and the beta feedback channel. A **suspected
vulnerability does not** — it is routed away from all of that, on purpose:

- It goes through **private disclosure**: GitHub Security Advisories
  (<https://github.com/hrishikeshdkakkad/fluidbox/security/advisories/new>) or email to
  **hrishidkakkad@gmail.com** with `[fluidbox security]` in the subject.
- It never goes in a shared beta channel, a public issue, or the feedback form.
- The maintainer acknowledges within **72 hours** and returns an assessment (confirmed /
  not a vulnerability / need more info) within **a week**, consistent with `SECURITY.md`.
- The reporter is credited in the advisory and changelog unless they prefer otherwise.
- The exploit details, the reporter's identity, and the report itself are kept confidential
  until a fix is available and coordinated disclosure is agreed.

This separation is also why the feedback form's security section asks only for impressions
of the posture and explicitly tells a participant who found a real weakness to stop and use
the private channel instead.

## How a participant withdraws and has their data deleted

At any time, for any reason or none, a participant may email the maintainer
(**hrishidkakkad@gmail.com**) with their participant ID and the word "withdraw". On receipt:

- Their questionnaire returns and their identity-mapping entry are deleted within **7 days**.
- The scorecard is recomputed without them; their row becomes empty and their absence is
  noted, not imputed.
- No reason is required, and withdrawal has no other consequence.
- A private security report already filed is governed by the security process and the
  reporter's wishes; withdrawing from the feedback beta does not retract a safety-relevant
  report, but the reporter may still ask to be de-identified in the eventual credit.

## Optional local instrumentation (opt-in, local-only, non-content)

The default above needs nothing more. But a participant who wants to help keep an accurate
funnel — without trusting their memory at the end — may keep a small **local** tally. This
is entirely opt-in, it is never installed or enabled by fluidbox, and nothing it records
ever leaves the participant's machine unless the participant later chooses to copy a value
into the questionnaire.

If a participant keeps such a tally, it must contain **only coarse, non-identifying,
non-content values** — the same fields the questionnaire already asks for, and nothing
else:

- Chosen install path (an enum: `just demo` / eval compose / from source / Kubernetes).
- Operating system, CPU architecture, container engine (enums).
- Whether the control plane reached healthy (a boolean).
- Time to first demo, in whole minutes (an integer).
- Count of governed runs completed (an integer).
- Count of real-repository runs completed (an integer — a **count only**, never a repo
  name, URL, or path).
- Count of gate decisions observed on the demo (an integer).
- Count of second-and-later governed runs (an integer).
- Which failure modes were hit (flags chosen from the troubleshooting guide's fixed list).
- The 0–10 recommendation score (an integer).

Explicitly out of bounds, even here: any prompt, any output, any code, any file path, any
repository name or URL, any token or key, any run diff or artifact.

- **Where it is stored:** a plain-text or JSON file the participant creates and owns — for
  example `~/fluidbox-beta-tally.md` or `~/fluidbox-beta-tally.json` in their home
  directory. It is a note to self, not a program fluidbox runs.
- **It is local-only:** it has no network path. fluidbox does not read it, send it, or know
  it exists. The only way any of it reaches the maintainer is if the participant opens the
  file, reads it, and types the values into the questionnaire.
- **How a participant inspects it before sending:** because it is a file the participant
  wrote in plain text, they inspect it by opening it in any editor and reading every line.
  There is nothing hidden to decode. Participants are asked to do exactly that — read the
  whole file — before transcribing anything, and to confirm it contains only counts and
  enums, no content and no secrets, before a single value goes into a return.

Because this local tally holds only the numbers the questionnaire already collects, opting
into it changes nothing about what the maintainer receives; it only helps the participant
report those numbers accurately.

---

## Participant-facing consent notice

> **fluidbox private beta — what you're agreeing to**
>
> Thanks for trying fluidbox. Taking part is voluntary, and you can stop at any time.
>
> We collect only what you choose to tell us in the feedback questionnaire: your operating
> system, CPU architecture, and container engine; your answers to the questions; and a
> pseudonymous participant ID. We derive some simple funnel numbers from those answers.
>
> We never collect your prompts, your model's output, your code, your repository contents,
> your file paths, your API keys or tokens, or any run data. The fluidbox software does not
> phone home — there is no automatic collection of anything. Everything we receive is
> something you typed on purpose. Please don't paste code, paths, secrets, or run diffs
> into the form; we don't want them.
>
> Your answers are pseudonymous. Your name and contact are stored separately from your
> answers and are used only to reach you. Only the maintainer sees raw returns; anything
> published is pooled and non-attributed.
>
> If you think you've found a security problem, please don't put it in the form or a shared
> channel — report it privately through GitHub Security Advisories or email
> hrishidkakkad@gmail.com with `[fluidbox security]` in the subject. You'll hear back within
> 72 hours and get an assessment within a week.
>
> You can withdraw and have your data deleted at any time by emailing hrishidkakkad@gmail.com
> with your participant ID and the word "withdraw"; we'll delete your returns within 7 days.
>
> By returning the questionnaire, you consent to this use of your feedback.
