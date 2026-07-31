# fluidbox private beta — feedback questionnaire

This is the questionnaire sent to each beta participant. It is an instrument: every
answer field below is deliberately blank, to be filled in by the participant.

## Before you start

**What we do with your answers.** Your responses feed a single manual scorecard
(`metrics-scorecard.md`) that decides whether the beta met its bar. We aggregate the
closed questions across all 20 participants and read the open ones individually. Nothing
here is published with your name attached; only pooled, non-attributed numbers and
paraphrased themes ever leave the maintainer's hands.

**What we never ask for, and never want.** Do not paste — and we will never request —
your prompts, model output, repository contents, source code, file paths from a private
repository, API keys, tokens, `.env` contents, or the admin token from `.demo/`. The
software does not phone home; there is no automatic collection. Everything in this form is
something you choose to type. If a question could only be answered by revealing any of the
above, leave it blank and say so.

**Security issues do not go here.** If you think you found a vulnerability (a tool call
that ran despite a deny, a credential reaching a sandbox or a log, an approval you could
forge, a fork-PR trust escalation, a budget bypass, or anything that breaks the security
model), stop and use private disclosure instead — see the *Security observations* section
and `data-and-privacy.md`. Do not describe an exploit in this form.

**Identity.** You have been given a pseudonymous participant ID (P01–P20). Put it below.
Your name and contact are held separately from these answers and are used only to reach
you; they are never part of the analysed dataset.

- Participant ID: `___`
- Date completed: `___`
- Did anyone help you fill this in, or is it solely your own experience? `___`

---

## 1. Environment

Report only your operating system, CPU architecture, and container engine. Nothing here
identifies you or your employer.

- Operating system: `[ ] macOS   [ ] Linux   [ ] Windows (incl. WSL2)   [ ] other: ___`
- CPU architecture: `[ ] arm64 (Apple Silicon / Graviton / aarch64)   [ ] amd64 (x86-64)   [ ] other: ___`
- Container engine: `[ ] Docker Desktop   [ ] colima   [ ] OrbStack   [ ] Docker Engine (native Linux)   [ ] other: ___`
- Which install path did you take first? `[ ] just demo (keyless)   [ ] Docker eval compose   [ ] develop from source   [ ] Kubernetes/Helm   [ ] other: ___`
- Had you used fluidbox before this beta? `[ ] no   [ ] yes`

> Note for context, not a question to answer: this candidate was validated only on a
> macOS arm64 host running Linux arm64 containers. amd64, a native Linux host, and Windows
> are unvalidated for this release, so your environment line is genuinely useful signal.

---

## 2. The install attempt

- Did you attempt an installation at all? `[ ] yes   [ ] no`  — if no, skip to section 9.
- Which prerequisites did you already have vs. install now? (Docker, Rust, just, Node/pnpm, Postgres): `___`
- Did you reach a **running stack** — a control plane that answered health and let you create a run? `[ ] yes   [ ] no   [ ] partly`
- If no or partly, what stopped you? `___`
- Roughly how long from your first command to a running stack (minutes)? `___`  `[ ] I didn't time it`
- Did `just doctor` (if you ran it) help? `[ ] didn't run it   [ ] yes   [ ] no`  — what did it miss? `___`

Open: describe the install in one or two sentences, including anything that surprised you.

`___`

---

## 3. The first demo (`just demo`)

The keyless demo is a deterministic replay through the real gate; it needs no API key and
makes no model calls.

- Did `just demo` complete and print the diff + cost + security receipt? `[ ] yes   [ ] no   [ ] didn't run it`
- Time from starting `just demo` to first seeing a governed-run receipt (minutes): `___`  `[ ] I didn't time it`
- On the first run, did it compile the control plane from source first? `[ ] yes   [ ] no   [ ] unsure`
- How many server-side gate decisions did the security receipt report? `___`
- Did you see the approval pause (the run waiting for your decision)? `[ ] yes   [ ] no`
- Did you see a policy **deny** naming a matched pattern? `[ ] yes   [ ] no`
- What cost did the receipt show? `___`  (expected: `$0.00`, 0 model requests)
- Did the demo tear itself down cleanly when you were done? `[ ] yes   [ ] no   [ ] I kept it up`

Open: did the demo make it clear *what fluidbox does* and *why the gate matters*? What
was still unclear?

`___`

---

## 4. Any governed run

A "governed run" here means a run that reached a terminal state with at least one
server-side gate decision — the demo counts.

- How many governed runs did you complete in total (including the demo)? `___`
- Did you start a **second** governed run after your first? `[ ] yes   [ ] no`
- If you ran more than once, why did you come back? `___`
- Did you try autonomous mode (no human approvals)? `[ ] yes   [ ] no`  — how did it behave? `___`
- Did any run pause on tooling you expected to be allowed? `[ ] yes   [ ] no`  — which tools? `___`

Open: anything about the run lifecycle — freeze, sandbox, gate, approval, diff, cost —
that felt wrong, slow, or missing?

`___`

---

## 5. Real-repository use

A "real-repository run" is a governed run against a repository you supplied, not the
shipped demo fixture.

- Did you point fluidbox at a repository of your own? `[ ] yes   [ ] no`
- If yes, roughly what kind of repo (language/size only — no names, no paths)? `___`
- How many real-repository runs did you complete? `___`
- Did the diff reflect real changes, or was it empty/zero-byte? `[ ] real changes   [ ] empty/zero-byte   [ ] n/a`
- If the diff was empty but the run reported success, tell us — this is a known and serious
  failure mode and we want every instance: `___`

Open: would you trust this to run against a repository that matters to you, and what would
have to be true first?

`___`

---

## 6. Integrations

- Did you activate any integration (GitHub App, an OAuth or API-key connection, a custom
  MCP server, a trigger/schedule)? `[ ] yes   [ ] no`
- Which one(s)? `[ ] GitHub   [ ] OAuth connection   [ ] API-key connection   [ ] custom MCP server   [ ] trigger/schedule   [ ] other: ___`
- Did it connect and work end to end? `[ ] yes   [ ] no   [ ] partly`  — what broke? `___`

Open: which integration, if it existed or worked better, would make fluidbox useful to
you specifically?

`___`

---

## 7. Failures encountered

Tick every failure you hit; add detail below. These map to the troubleshooting guide.

- `[ ]` Docker could not share the checkout / empty workspace / empty diff
- `[ ]` "No such image" after preflight passed (docker context vs `DOCKER_HOST`)
- `[ ]` First run looked hung while it was compiling from source
- `[ ]` Port already in use (19790 / 19791 / 15434 or 8787 / 3000)
- `[ ]` After an upgrade, every supervised run paused on ordinary tooling
- `[ ]` Control plane never became healthy (demo timed out and tore down)
- `[ ]` Missing Docker / Docker not running
- `[ ]` Missing or rejected credential (admin token, model key)
- `[ ]` Leftover containers / volumes / ports after teardown
- `[ ]` Something else: `___`

For each ticked box, what was the symptom, and did the tool's error message tell you the fix?

`___`

---

## 8. Security observations

This section is for your *impressions* of the security posture, not for reporting a
vulnerability. If you found an actual weakness, do not describe it here — use private
disclosure (below).

- Did the boundaries feel honestly described? Were you ever told something was safe that
  was not? `[ ] honest   [ ] oversold   [ ] undersold`  — where? `___`
- Did you understand that the Docker default sandbox network mode (`HostDev`) is *not* an
  egress boundary — it has general internet access and the host's network position?
  `[ ] yes, this was clear   [ ] no, this surprised me`
- Did you run the eval Docker profile on a shared or untrusted network? `[ ] no   [ ] yes`
  (its API port is published on all interfaces and the admin token is the only protection.)
- Did you run `just gate-proof` or read its output? `[ ] yes   [ ] no`  — was it convincing? `___`

**If you believe you found a vulnerability:** do not fill in details above. Report it
privately via GitHub Security Advisories
(<https://github.com/hrishikeshdkakkad/fluidbox/security/advisories/new>) or email
**hrishidkakkad@gmail.com** with `[fluidbox security]` in the subject. You will get an
acknowledgement within 72 hours and an assessment within a week. Never post it in a shared
beta channel or a public issue.

- Do you have a private security report in flight for this beta? `[ ] no   [ ] yes (already sent privately)`

---

## 9. Recommendation intent

On a scale of **0 to 10**, how likely are you to recommend fluidbox to a colleague who has
a fitting use case (governing AI coding agents in disposable, audited sandboxes)?

Score: `___`

Anchors, so the number means the same thing for everyone:

- **0** — I would actively warn people away from it.
- **5** — Neutral; I would not bring it up unprompted.
- **7–8** — I would mention it if asked, with caveats.
- **10** — I would actively recommend it to a colleague with a fitting use case.

- The single biggest reason for your score: `___`
- Who is the colleague you had in mind (role/use case only, no names)? `___`
- What one change would move your score up by two points? `___`

---

## 10. Contribution interest

- Would you consider contributing to fluidbox? `[ ] no   [ ] maybe   [ ] yes`
- In what form? `[ ] code   [ ] documentation   [ ] policies   [ ] connectors/integrations   [ ] security hardening   [ ] bug reports   [ ] other: ___`
- Is there a specific thing you would want to build or fix? `___`
- May we follow up with you about it? `[ ] no   [ ] yes` (this uses your separately-held
  contact detail, not these answers.)

---

## Anything else

The one thing this questionnaire failed to ask about:

`___`

Thank you. Your return is what turns this beta from an anecdote into a measurement.
