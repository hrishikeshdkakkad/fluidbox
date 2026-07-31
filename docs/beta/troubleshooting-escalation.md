# fluidbox private beta — troubleshooting and escalation

Diagnose first, fix second, escalate only what needs it. This guide starts from the
**symptom a participant actually sees**, names the real cause, gives the fix, and says
plainly whether it is a product defect or an environment issue — because the two go to
different places. The escalation rules at the end govern where anything unresolved goes,
and the one rule that overrides all others: a suspected vulnerability is disclosed
privately and never in a shared channel.

## Diagnosis table

| Symptom (what you see) | Actual cause | Fix | Defect or environment |
|------------------------|--------------|-----|-----------------------|
| The demo "succeeded" but the diff is empty / zero bytes; the security receipt says "ZERO gate decisions"; commands report "No such file or directory". | The Docker daemon cannot bind-mount your checkout, so `/workspace` mounted **empty** and nothing could run. Common on colima (shares `$HOME`, not `/tmp`) or a directory outside Docker Desktop's File Sharing list. | On this release `just demo` runs a mount probe and **refuses** with the fix inline. If you hit the empty result on another path: clone under `$HOME`, or add the directory to Docker Desktop → Settings → Resources → File Sharing (or restart colima with `--mount "$(pwd):w"`), then re-run. | Environment. The historical *false success* was a product defect; the demo now detects and refuses it. |
| `just demo` dies at preflight: "the docker daemon cannot read files from this checkout … mounted as an EMPTY directory." | Same root cause as above, caught early by the mount probe before any run is created. | Follow the printed instruction: move the checkout under `$HOME` or share the directory; re-run. | Environment (the refusal itself is correct product behavior). |
| Preflight passes, then the run fails at `initializing` with `No such image: fluidbox-replay-runner:dev` (or the sandbox image). | The docker **CLI** honours `docker context`; the control plane's client (bollard) reads `DOCKER_HOST` and otherwise the default socket and does not know contexts exist. On a multi-daemon machine they resolve to different daemons — the image lives on one, the server dials the other. | The demo now resolves and **exports one endpoint** so every call agrees. If you drive runs outside the demo, `export DOCKER_HOST=` the daemon that actually holds the images (`docker context inspect <ctx> --format '{{.Endpoints.docker.Host}}'`). | Environment (multi-daemon host); the demo mitigates it. |
| `just demo` sits for several minutes at "first run: compiling the control plane"; looks hung. | The keyless demo builds `fluidbox-server` from source on the first run — a cold Rust build takes minutes. | Wait; it is one-time and later runs skip it. Confirm progress via CPU use or the cargo output. It is not a hang. | Expected behavior, not a defect. |
| "port 19790 (needed for the fluidbox API) is already in use" (or 19791 / 15434). | Another process — often a previous demo that did not tear down, or an unrelated service — holds the port. | Free the port, or set the named override the message prints: `FLUIDBOX_DEMO_PORT`, `FLUIDBOX_DEMO_INTERNAL_PORT`, or `FLUIDBOX_DEMO_DB_PORT`. `just demo-down` first if a prior demo is the culprit. | Environment. |
| "control plane did not become healthy in 60s" followed by the last log lines and automatic teardown; exit code 2. | The control plane never answered health inside the bounded 60-second wait — usually the demo Postgres port is unreachable or a migration failed (named in the log). | Read the printed tail and the full `.demo/server.log`; fix the named cause (port, migration) and re-run. The demo tears itself down and exits non-zero on purpose — this is fail-closed, not a leak. | Usually environment (port/DB); a genuine migration bug would be a product defect. |
| After upgrading an existing deployment, **every supervised run pauses** for approval on ordinary agent tooling (or autonomous runs deny it). | The seed policy never re-applies over a stored policy, and this candidate makes the gate mandatory over 23 newly-advertised tool names that have no rule — so they fall to `defaults.tool_action`. | Import `policies/default.yaml` with `POST /v1/policies` (it appends a version; byte-equal content is a no-op) or add the rules on the Governance page. Fresh installs, including `just demo`, already carry the new rules, so this hits upgraders only. | Product behavior, documented as an upgrade step; needs one operator action. |
| "missing required command: docker", or "Docker is not running." | No Docker engine installed, or the daemon is stopped. | Install Docker Desktop, OrbStack, or colima; start it and wait until ready; re-run. `just demo` needs no API key, only a running Docker. | Environment. |
| `docker compose ... up` on the eval profile refuses to start and names `FLUIDBOX_ADMIN_TOKEN`. | The eval profile now **requires** an admin token — the old repo-published default was removed because the API port is published on all interfaces. | `export FLUIDBOX_ADMIN_TOKEN=$(openssl rand -hex 32)` and re-run. Run this profile only on a network you trust; its dashboard is loopback-only but its API port cannot be. | Environment/config; the required-token change is a deliberate security fix. |
| A **live** model run (not the demo) fails to call a model, or is rejected. | The keyless demo needs no key; a live Claude run needs `ANTHROPIC_API_KEY` (in the LiteLLM container only), and a Codex run needs `OPENAI_API_KEY`. A key with no credit fails at the model call. | For the demo, no key is needed — you may be on the wrong path. For a live run, supply a funded key of the right provider. Note: no live **Claude** run was validated for this candidate (the maintainer's key was out of credit); a live **Codex** run was. | Environment/config. |
| Control plane exits, or `/v1/health` never comes up, or runs stick at `initializing`. | Database unreachable or a pooled (not direct) `DATABASE_URL`; a loopback `FLUIDBOX_BIND` (must be `0.0.0.0`, so sandboxes reach it over `host.docker.internal`); or a migration failure. | Run `just doctor` — it checks exactly these. Read `server.log`. Use a direct Postgres connection string and bind `0.0.0.0`. | Usually environment/config. |
| Leftover containers, volumes, or a held port after a demo; or worry the demo touched your dev stack. | A hard kill (SIGKILL) can strand a per-run `fluidbox-net-*` network or an orphaned container; normal teardown is clean and never touches `just dev`. | `just demo-down` is idempotent: it reaps an orphaned demo control plane by argv match, removes the demo containers and volume, and deletes `.demo/`. For a stray, remove that named resource specifically — **do not** `docker system prune` or a bare `volume rm`, which would hit your dev stack. | Mostly environment/expected; the demo is designed not to touch the dev stack. |
| "Everything looks fine but the diff is empty" — the run reports success yet nothing changed, on any path. | This **is** the empty-workspace failure (first row): the daemon could not share the checkout, so the agent saw an empty `/workspace`. The tell is a zero-byte diff **and** zero gate decisions. | Treat any empty-diff, zero-decision "success" as this failure until proven otherwise. On the demo the mount probe now prevents it; on the eval profile or a hand-rolled run, verify the workspace path is shareable (under `$HOME` / in File Sharing) before trusting the result. | Environment (daemon file sharing); the false-success that made it dangerous was a product defect, now fixed in the demo. |

## Escalation path

Once diagnosed, anything a participant cannot resolve is escalated by severity. The
maintainer is a single person (fluidbox is pre-1.0), so "who is contacted" is short — but
the channel differs sharply between security and everything else.

**Severity levels.**

- **S0 — security or a broken guarantee.** A tool call that executed despite a deny; a
  credential, secret, or prompt reaching a sandbox, a log, the ledger, or an API response;
  a fork-PR trust escalation; a forged or replayed approval; a budget/metering bypass; any
  break of the security model in `SECURITY.md` / `docs/ARCHITECTURE.md`. Also: any sign the
  software exposed a participant's data. **Route: private disclosure only.**
- **S1 — onboarding blocker.** A participant cannot reach a running stack or a governed run,
  or the same failure has now hit multiple participants. Route: the beta feedback channel to
  the maintainer.
- **S2 — bug with a workaround.** Something is wrong but there is a documented path around
  it. Route: beta feedback channel; queued.
- **S3 — cosmetic, docs, or nice-to-have.** Route: beta feedback channel; batched.

**Who is contacted, and how fast.**

- **S0 (security):** the maintainer, through **GitHub Security Advisories**
  (<https://github.com/hrishikeshdkakkad/fluidbox/security/advisories/new>) or email to
  **hrishidkakkad@gmail.com** with `[fluidbox security]` in the subject. Consistent with
  `SECURITY.md`: acknowledgement within **72 hours**, assessment (confirmed / not a
  vulnerability / need more info) within **a week**. These are the project's stated security
  timelines and this beta does not shorten or contradict them.
- **S1–S3 (non-security):** the maintainer, through the beta feedback channel or the
  participant's assigned contact. During an active beta the target is same-day
  acknowledgement for S1 and best-effort for S2/S3. These are beta operating targets, not
  the `SECURITY.md` guarantee — do not conflate the two.

**The overriding rule.** A **suspected vulnerability always goes through private
disclosure and never a shared/group channel or a public issue.** When in doubt about
whether something is a security issue, treat it as one and use the private channel — the
cost of a mistaken private report is nothing, the cost of a public one can be real. Never
post exploit detail, tokens, or a private-repo diff into a shared beta channel, even to ask
whether it matters.
