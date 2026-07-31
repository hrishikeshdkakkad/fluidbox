# fluidbox private beta — installation observation sheet

One sheet per participant, per install session. Fill it in **while you watch**, not from memory afterwards. Every value field is intentionally blank (`___` or an empty `[ ]`); leave a field blank if it did not occur rather than inventing a value. This sheet is plain text — usable on paper, in a terminal, or in any editor, with no special tooling.

Do **not** record anything the participant did not actually do or say. If you did not observe it, the field stays blank.

---

## A. Session header

- Participant slot (P-01 … P-20): `___`
- Persona (Platform/K8s · AI-agent · Security · Backend/OSS): `___`
- Facilitator: `___`
- Date: `___`   Start time: `___`   End time: `___`
- Candidate SHA / tag observed: `___`
- Observation mode: `[ ]` live screen-share  `[ ]` in person  `[ ]` async report

## B. Environment

Record what is actually on the machine, not what the participant thinks is on it.

- OS and version: `___`
- Architecture: `[ ]` arm64  `[ ]` amd64  `[ ]` other: `___`
  - *(Reminder: only macOS arm64 host + Linux arm64 containers is validated. Anything else is itself a finding.)*
- Docker engine: `[ ]` Docker Desktop  `[ ]` OrbStack  `[ ]` colima  `[ ]` other: `___`   Version: `___`
- Docker context / `DOCKER_HOST` set?: `___`
- Rust toolchain present before starting?: `[ ]` yes  `[ ]` no   `cargo` version: `___`
- Node + pnpm present? (from-source path only): `[ ]` yes  `[ ]` no
- python3 present?: `[ ]` yes  `[ ]` no
- Checkout location: `[ ]` under `$HOME`  `[ ]` `/tmp` or elsewhere: `___`
- Network context: `[ ]` trusted  `[ ]` untrusted / shared  `[ ]` unknown
- Install path chosen: `[ ]` `just demo` (keyless)  `[ ]` Docker eval  `[ ]` from source  `[ ]` other: `___`

## C. Timestamped milestones

Record the wall-clock time each milestone is reached. Blanks mean "not reached." The span from the first install command to "first demo complete" is the time-to-first-demo metric — **do not stop the clock for the cold compile.**

| Milestone (mapped to funnel stage) | Time reached |
|---|---|
| Clone started | `___` |
| First install command run (**install attempt**) | `___` |
| Cold compile started — `[ ]` cold  `[ ]` warm (binary already present) | `___` |
| Compile finished | `___` |
| Replay / runner image build started | `___` |
| Image build finished | `___` |
| Control plane healthy (**stack ready**) | `___` |
| Approval pause reached | `___` |
| First demo complete — receipt printed (**first demo**) | `___` |
| Gate decisions observed (expected: 3 allow · 1 deny `\bcurl\b` · 1 human-allow) | count: `___` |
| Live run attempted — `[ ]` Codex  `[ ]` Claude | `___` |
| First **governed-run completion** (demo or live) | `___` |
| **Real-repository run** completed | `___` |
| **Second run** completed (separate sitting) | `___` |
| **Integration activated** — which: `___` | `___` |

Total time, first install command → first demo complete: `___`

## D. Errors — verbatim

Copy the exact text of every error. Add blocks as needed. Paraphrase nothing.

**Error 1**
- Stage it occurred at: `___`
- Verbatim text:
  ```
  ___
  ```
- What the participant tried in response: `___`
- Resolved?: `[ ]` yes  `[ ]` no   How: `___`

**Error 2**
- Stage it occurred at: `___`
- Verbatim text:
  ```
  ___
  ```
- What the participant tried in response: `___`
- Resolved?: `[ ]` yes  `[ ]` no   How: `___`

*(Watch specifically for the known failure modes — empty-workspace bind mount, `No such image` / daemon-endpoint mismatch, a slow first run mistaken for a hang, a port collision on 19790/19791/15434, and the seed-policy-not-reapplied case on an upgraded deployment. If one occurs, note it here and flag it for the recurring-failure list.)*

## E. Recovery and support

- Did the participant recover **unaided**?: `[ ]` yes, fully unaided  `[ ]` yes, but only after facilitator help  `[ ]` no, remained blocked
- If facilitator intervened: at what stage, and what did you have to say?: `___`
- What was missing from the documentation that would have prevented the need to intervene?: `___`
- Approx. facilitator time spent helping (minutes): `___`

## F. Severity classification

Classify anything that went wrong, using the beta's scheme. Leave blank if nothing qualified.

- `[ ]` **P0** — unauthenticated/low-privilege code execution or data disclosure on a default path, or a public claim measurably false in a way a user relies on. *(Triggers early halt — see the plan.)*
- `[ ]` **P1** — materially misleads an operator, or removes a control the docs say exists; blocks launch unless accepted in writing.
- `[ ]` **P2** — real, bounded; ship-with-disclosure.
- `[ ]` **P3** — correctness/quality debt, no launch-day consequence.
- Summary of the issue(s) classified above: `___`
- Is this a **new** finding or a rediscovery of a **documented** limitation?: `[ ]` new  `[ ]` known/documented
- Recurring? Seen in another participant already?: `[ ]` first occurrence  `[ ]` also seen in slot(s): `___`

## G. Security finding (if any)

If a security issue surfaced, **stop recording it here and take it private** (GitHub Security Advisory), then note only the minimum below. Do not paste an exploit into a sheet that might be shared.

- Security finding surfaced?: `[ ]` no  `[ ]` yes — routed privately at: `___` (time)
- Advisory / private tracking reference: `___`

## H. Free-form observations

Only what you actually saw or the participant actually said. Do not fabricate quotes.

- Where they hesitated or misread the docs: `___`
- Anything they expected that did not happen: `___`
- Notable spontaneous comments (verbatim, only if actually said): `___`
