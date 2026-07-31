# fluidbox private beta — facilitator guide

For the maintainer running the beta. The goal is honest evidence, not a good-looking funnel. The single most valuable thing you produce is an accurate record of what broke, for whom, and whether they recovered — so most of your job is to watch quietly and write things down.

Read [`private-beta-plan.md`](./private-beta-plan.md) first; this guide is how you execute it.

---

## 1. Before you invite anyone (Phase 0)

- Confirm the candidate is at a known, frozen SHA/tag: `0.4.0-rc.1` on `release/prime-time-rc`. Do not let it drift under the participants mid-beta; if you must patch, note the new SHA against everyone who installed after it.
- On a **clean** machine (or a fresh user account), run `just demo` and `just gate-proof` end to end. If either fails on your own clean environment, you are not ready to invite anyone.
- Stand up a **private** disclosure channel and confirm you can open a GitHub Security Advisory. Security findings must never land in a group chat or a public issue (§6).
- Have the instruments ready: one copy of [`installation-observation.md`](./installation-observation.md) per participant, the invitation ([`invitation-draft.md`](./invitation-draft.md)), and the participant guide ([`participant-guide.md`](./participant-guide.md)).
- Confirm the known-limitations list is current and will be shared with every participant (it is honest, and sharing it up front is what makes the "no live Claude run" and "HostDev is not a boundary" facts land as candour rather than as a caught omission).

## 2. Inviting and scheduling

- **Invite in waves, not all at once.** Start with the Phase 1 canary (2–4 participants, spread across personas, chosen for tolerance of rough edges). This ordering is the main defence of the "no onboarding failure affecting more than 2 participants" threshold — a systemic break is caught before it reaches a third person.
- **Recruit for platform spread.** Only macOS arm64 is validated. Deliberately seek amd64 hosts, at least one Linux host, and Windows if anyone volunteers; those unknowns are where the beta earns its keep.
- **Book a real window.** Offer each participant a scheduled 45–60 minute session where you can observe the install live (screen-share or in person). Async is acceptable for depth work (real-repo runs, second runs) but the *first* install is worth watching in real time.
- **Set expectations in the invite, not in the call.** Time ask, pre-1.0 security-software status, no live Claude validation, and "throwaway repos only" all belong in writing before they say yes.

## 3. Observing an install without leading it

The install is the experiment. If you talk a participant through it, you have destroyed the data.

- **Share the participant guide and then go quiet.** Let them read it the way a real adopter would. Watch where they hesitate, what they skip, and what they misread.
- **Narrate nothing.** Do not say "you'll want to clone under home" — the guide says it; the question is whether they *do* it. If they clone into `/tmp`, let them, and record whether the demo's own guardrail catches it and whether they recover from the message unaided.
- **Timestamp milestones as they happen** against the funnel stages in the observation sheet. You are capturing wall-clock to first demo, including the cold compile — do not pause your clock for it, and do record whether the compile was cold or warm.
- **Capture errors verbatim.** Copy the exact text, not your paraphrase. "It couldn't find the image" is not data; `No such image: fluidbox-replay-runner:dev` is.

## 4. What to say and what not to say

**Safe to say at any time:** "Take the path you'd take if I weren't here." "Read it however you normally would." "There's no wrong answer — I'm testing the docs, not you." "Tell me what you expected to happen."

**Do not say:** anything that supplies the fix before they have struggled — the daemon-endpoint export, the home-directory clone, the port override, the DOCKER_HOST hint. Each of those is a documented failure mode we are specifically measuring; handing over the answer converts a finding into a non-event.

**Never say** that a boundary is stronger than it is. If a participant assumes the default Docker sandbox is network-isolated, that assumption is itself a finding — note it, and correct it only after you have recorded that the documentation let them believe it.

## 5. Recording a failure, and when to intervene

Letting a participant struggle is the point — a struggle that ends in unaided recovery is the strongest possible evidence the docs work, and a struggle that ends in a stuck participant is the finding you most need. So intervene late and deliberately.

- **Let them work the problem** for as long as they are making progress, even slow progress. Record what they try.
- **Intervene when** they are truly blocked (no new idea for several minutes), when they are about to do something unsafe (run the eval profile on untrusted Wi-Fi, point a run at a real/sensitive repo), or when continuing would waste the session with no new signal.
- **When you do intervene, record it as a failure of the material**, not a success of the run: note the exact stage, what was missing from the docs, what you had to say, and classify severity (P0–P3 per the plan). "Recovered only with facilitator help" is a different — and more serious — data point than "recovered unaided," and the observation sheet has a field for exactly that distinction.
- **Watch for recurrence.** The moment the same failure appears in a second participant, flag it; if it would reach a third, that trips the onboarding-failure threshold and you pause the wave to fix or document it.

## 6. Handling a security finding responsibly

Pre-1.0 security software will attract security findings; that is a sign the right people are looking, not a crisis. Handle each one as coordinated disclosure.

- **Take it private immediately.** Move the conversation off any shared channel. Do not discuss specifics — not even "someone found an egress issue" — in a group setting where other participants can see it.
- **Open a GitHub Security Advisory** (draft) and capture the reproduction, the environment, and the participant's contact for credit. Honour the `SECURITY.md` acknowledgement commitment.
- **Classify against the P0–P3 scheme.** A P0 (unauthenticated/low-privilege code execution or data disclosure on a default path, or a public claim measurably false in a way a user relies on) **halts onboarding** — see the plan's early-halt section. Fix, re-verify (including `just gate-proof`), then resume.
- **Distinguish new from known.** Several boundary facts are already disclosed (the `HostDev` egress default, the eval-profile network exposure, the absent server-side bypass detection, the unsigned artifacts). A participant rediscovering a documented limitation is a documentation-clarity finding, not a new vulnerability — but confirm that before you conclude it, and thank them the same either way.
- **Never argue a finding down in the moment.** Record it, reproduce it yourself, then classify. The participant is doing you a favour.

## 7. Cadence

**Daily during Phases 1–2:** a short triage pass — new installs, new failures, anything recurring, anything security-flavoured routed private. Update the running failure list and the funnel counts (all still `___` until real). Confirm no failure has reached a third participant.

**Every 2–3 days during Phases 3–4:** check on depth — who reached a real-repository run, who came back for a second run, who activated an integration. Nudge (do not push) participants who stalled after their first demo; a stall is itself worth understanding.

**Continuously:** keep the observation sheets complete. A half-filled sheet a week later is a guess, and this beta's whole worth is that it does not guess.

## 8. Closing the beta out (Phase 4)

- **Send the exit survey** to everyone who attempted, including those who did not finish — a participant who bounced at the cold compile is as informative as one who ran ten times. Capture recommendation intent and contribution interest here.
- **Synthesise the funnel.** Fill in every `___` in the plan's funnel and threshold tables from the observation sheets and the survey. State plainly which of the eight thresholds were met and which were not; do not round a near-miss up.
- **Consolidate findings** by severity, de-duplicated across participants, each with its reproduction and environment. Note which recurred and how many participants each affected.
- **Write the recommendation** for the next gate (RC → public launch): what the beta proved, what it did not, which limitations remain open, and whether the evidence supports moving past LIMITED BETA. Ground it in the collected numbers, not in impressions.
- **Close the loop with participants.** Tell them what you found and what you are doing about it, credit security reporters (with their consent), and confirm everyone has torn their stacks down — no lingering admin tokens or exposed APIs.
