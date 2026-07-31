# fluidbox private beta — participant guide

Thank you for testing `0.4.0-rc.1`. This is pre-1.0 security software and a **release candidate that has not been published**. Nothing here is hype; where a thing has not been validated, this guide says so.

The fastest honest first success takes no API key at all. Start there.

---

## 1. What you are running, in one paragraph

fluidbox runs an AI coding agent inside a fresh, disposable sandbox, decides every tool call against a policy **before** it executes, pauses for your approval when the policy says so, and ends with a diff and a cost report. The first thing you will run is a **deterministic replay** — a scripted agent, clearly labelled, making no model calls — driving the *real* control plane, the *real* policy gate, and a *real* sandbox container. It is the honest way to see the whole loop work in a few minutes without spending a cent.

## 2. Before you read further — two safety facts

Please internalise these before you run anything. They are true of this candidate by design, not by oversight.

- **The default Docker sandbox network (`HostDev`) is not an egress boundary.** It has general internet access and your host's network position. It is deliberately convenient for trying the loop; it is *not* a containment wall. Only Kubernetes `zeroEgress` and Docker `Hardened` mode close it. **Do not point a run at anything sensitive**, and do not treat the default sandbox as isolated from your network.
- **The Docker eval profile publishes its API on all network interfaces.** This is by necessity — sandboxes reach the control plane over `host.docker.internal` — so the API cannot be bound to loopback. Its dashboard *is* loopback-only, and a required admin token is the only thing protecting the API. **Run it only on a network you trust**, never on café or hotel Wi-Fi or a shared LAN.

More generally: point runs at **throwaway or test repositories only** — never a repo with secrets, personal data, or anything you would not paste into a public issue.

## 3. Prerequisites

For the keyless demo (the recommended first path):

| Tool | Why | Note |
|---|---|---|
| Docker | runs the sandbox container and the demo's Postgres | Docker Desktop, OrbStack, or colima all work |
| git | the control plane snapshots workspaces with git | |
| [just](https://github.com/casey/just) | the command runner | |
| Rust ([rustup](https://rustup.rs)) | the first demo run **compiles the control plane from source** | one-time; see §5 |
| python3 | the demo's timeline watcher and JSON glue | ships with macOS; `apt/dnf install python3` on Linux |

`curl` and `openssl` are used too; both ship with macOS and are a package away on Linux.

**Platform honesty.** Only a **macOS arm64 host running Linux arm64 containers** has been validated for this candidate. amd64 hosts, Linux hosts, and Windows were **not** tested. If you are on any of those, you are genuinely helping us find out whether it works — please report what happens either way.

## 4. Clone under your home directory (this matters)

Clone somewhere your Docker daemon can share — **under your home directory is the safe choice**:

```bash
cd ~
git clone https://github.com/hrishikeshdkakkad/fluidbox.git
cd fluidbox
```

The reason is concrete, not superstition. fluidbox bind-mounts the run's workspace from disk into the sandbox. If your checkout is somewhere the daemon does not share — a `/tmp` checkout on colima, or a directory outside Docker Desktop's File Sharing list — Docker does not error; it mounts an **empty** directory, and the run then "succeeds" while proving nothing. The demo now detects this and refuses with the exact fix, but you avoid the whole class by cloning under `$HOME`.

## 5. The keyless demo — your first success

```bash
just demo
```

**What to expect on timing.** The very first run compiles the Rust control plane from source and builds the replay image. On a cold cache this is **several minutes** — this is normal, not a hang. The demo prints `first run: compiling the control plane` when it happens; later runs skip it. Once the binary and image exist, the run itself is fast — about twelve seconds in the validated environment.

**What a successful run looks like.** The demo drives one governed run and pauses for **your** approval partway through. In the validated environment it produced exactly **five gate decisions**:

- **three policy-allow** (the ordinary edit/test tooling the policy permits),
- **one policy-deny** — a blocked command, with the receipt naming the matched pattern `\bcurl\b`, and
- **one human-allow** — released only after the approval pause, recorded in the audit ledger as `approved_once`.

It ends with a real diff (the fixture's `app.js` repaired and a `deploy.log` written), and a cost line reading **`$0.00 · 0 model requests · 5 tool calls`** — the zero is a property of replay mode, not an empty run. Everything printed is read back from the control plane, not asserted by the script.

If instead you see a failure banner naming a terminal state, the demo failed and says so loudly (it exits non-zero and prints troubleshooting rather than next-steps). The most common cause is a Docker endpoint mismatch — see §9.

## 6. Prove the gate yourself, still without a key

If you want to see the permission gate enforced directly — no replay, no model, no spend — run:

```bash
just gate-proof
```

This drives the real runner image and the real pinned CLI against a mock upstream and a mock control plane whose verdict each scenario chooses. It makes **14 assertions**, including that a denied read-only command does **not** execute, allow-path positive controls (so a "nothing happened" result cannot be an accident), a verdict held open for six seconds with the resulting side effect appearing 37 ms *after* the allow, and five fail-closed variants. This is the acceptance test the earlier gate defect got past; security-minded participants should start here.

## 7. Graduating to a live agent

The demo makes no model calls. To run a *real* model under the same governance, you have two options. Be precise about which one you are on.

**Live Codex (validated for this candidate).** A live Codex run was exercised for `0.4.0-rc.1` (OpenAI, model `gpt-5.4-mini`) at a total cost of **$0.0031 for two runs**. Build the Codex runner, add your own OpenAI key, and run:

```bash
just codex-build
# add OPENAI_API_KEY=sk-... to .env
just dev
```

**Live Claude (not validated for this candidate).** The maintainer's Anthropic key is out of credit, so **no live Claude run was validated for this release candidate.** If you have your own funded Anthropic key you can try it — and you would be the first to exercise this path on this candidate, so please report exactly what happens:

```bash
# add ANTHROPIC_API_KEY=sk-ant-... to .env  (only the LiteLLM container ever sees it)
just demo-down && just dev
cargo run -p fluidbox-cli -- run --task "fix the failing test" --repo scripts/demo-fixture
```

Either way, model spend is metered and shown per run. The demo's `$0.00` becomes a real (small) number; the validated Codex figure above is your best available reference point.

## 8. Trying a real repository

Once the live path works for you, point it at a repository — a **throwaway or test** one (§2), never something with secrets or PII:

```bash
cargo run -p fluidbox-cli -- run \
  --repo ~/path/to/a/disposable/repo \
  --task "find and fix the failing test"
```

The original repository is never the working tree — the control plane fetches a disposable copy and the agent only ever sees that. You will get the same timeline, gate decisions, approval pauses, diff, and cost as the demo, but against your own code.

## 9. When something goes wrong

The failure modes below were found during validation and are worth knowing before you hit them.

- **The demo "succeeds" but nothing changed / an empty workspace.** Your daemon cannot share the checkout. Re-clone under `$HOME` (§4); on colima you can instead restart with `--mount "$(pwd):w"`, and on Docker Desktop add the directory under Settings → Resources → File Sharing.
- **`No such image` when running by other means.** The docker CLI honours `docker context`; the control plane reads `DOCKER_HOST`. The demo resolves and exports one endpoint for you, but if you start the server another way, export `DOCKER_HOST` to the daemon that actually holds the images. The demo prints the endpoint it resolved in its preflight — check it against where your images live.
- **A slow first run.** That is the cold Rust compile (§5), not a hang. Wait it out; subsequent runs are fast.
- **A port is already in use.** The demo uses `19790`, `19791`, and `15434`, and refuses with the exact override variable (for example `FLUIDBOX_DEMO_PORT=<port> just demo`) if one is taken. Free the port or override it.
- **You already had an older fluidbox installed.** The seed policy does **not** re-apply over a policy already stored in your database. A fresh clone gets the complete, correct seed policy; an upgraded deployment does not, and every supervised run will then pause on ordinary agent tooling. If you are upgrading rather than starting fresh, import the current policy first: `POST /v1/policies` with `policies/default.yaml` (a byte-equal import is a no-op). Fresh installs need not worry about this.

## 10. Tearing everything down

The demo is fully isolated (its own compose project, ports, Postgres volume, and state under `.demo/`) and offers to clean up when it finishes. To remove every trace at any time:

```bash
just demo-down
```

If you brought up the eval profile or `just dev`, stop those the way you started them (`docker compose -f deploy/docker-compose.eval.yml down -v`, or Ctrl-C plus `just db-down` / `just gateway-down`). When in doubt, ask the facilitator — leaving a live admin token or an exposed API running is exactly what we are trying to help you avoid.

## 11. What to send back

Keep it light. The facilitator will ask for: which install path you took, your OS/arch/docker engine, where it succeeded or stalled, any error **verbatim**, whether you recovered on your own, and — at the end — whether you would recommend fluidbox for its intended use and whether you would consider contributing. If you find a **security** issue, do **not** post it in a shared channel or a public issue; report it privately through GitHub Security Advisories or straight to the facilitator.
