# `just demo` validation — 2026-07-29

Machine: the maintainer's laptop, with the regular dev stack (`just dev`,
ports 8787/8788/5433/4000/3000) left RUNNING throughout — the demo's isolation
claim was validated against live contention, not an empty machine. Engine:
colima (Docker Desktop was refusing writes with a full disk at the time; the
demo honors `DOCKER_HOST` like every docker tool). Server binary: prebuilt via
`FLUIDBOX_DEMO_SERVER_BIN` (the from-source path was exercised once — the
first-run compile message and `cargo build` flow — before disk pressure made
prebuilt the responsible choice for repeated drills).

Every transcript here is the raw, uncut output of `scripts/demo.sh`.

| Drill | File(s) | Result |
|---|---|---|
| (a) approve path, end-to-end | `drill-a-approve.txt`, `approve/` (events, cost, artifacts, approvals, session JSON + diff patch + live `docker inspect` of the sandbox) | PASS — 5 gate decisions (3 policy-allow, 1 policy-deny incl. the matched regex, 1 human-allow); diff shows the fix AND `deploy.log`; $0.00 / 0 model requests; full teardown |
| (b) deny path | `drill-b-deny.txt`, `deny/` | PASS — human deny ledgered (`source=human`), `deploy.log` absent from the diff, run still `completed`: “Deploy withheld — nothing was released.” |
| (c) approval TTL → auto-deny | `drill-c-timeout.txt`, `timeout/` | PASS — untouched prompt auto-denies at the policy's 180s TTL (`approval.decided: denied by timeout`, `tool.decision: deny, human:timeout`); run still completes (“Deploy withheld”); total 191s |
| (d) Ctrl-C / TERM mid-run | `drill-d-interrupt.txt` | PASS — SIGINT delivered to the process group at the approval pause: exit 130, server + sandbox container + volume + `.demo/` all removed, port free (audited) |
| (e) repeated invocation | `drill-e-double-invoke.txt` | PASS — refused with the pid and the exact `just demo-down` remedy; no state mutated |
| (f) port collision | `drill-f-port-collision.txt` | PASS — names the port, the listening process (lsof line), and the `FLUIDBOX_DEMO_PORT` override; exits before creating state |
| (g) docker daemon down | `drill-g-docker-down.txt` | PASS — “Docker is not running” + start instructions; exits before creating state |
| (h) health timeout | `drill-h-health-timeout.txt` | PASS — never-healthy server binary: bounded 60s wait, last log lines + log path + likely causes printed, automatic teardown, exit 2 (also organically reproduced once via the from-source fallback against a missing binary) |
| missing API keys | every transcript's banner + next-steps block | PASS — replay needs none (stated up front); next-steps branch on key presence |

Bugs found BY these drills and fixed in `scripts/demo.sh` during validation:
1. Orphaned control plane after an external SIGTERM burst (pidfile died with
   `.demo/` while the disowned server survived) — teardown now also reaps any
   `fluidbox-server` listening on the demo port, verified by process name so a
   foreign listener is never touched.
2. Watcher output invisible under redirection (python block buffering) —
   watcher and receipt renderers now run `python3 -u`.
3. Approval prompt grammar (“you denyd”).
4. Ctrl-C swallowed by bash's cooperative-SIGINT rule when the python watcher
   converted the signal into a normal exit — the watcher now dies BY SIGINT
   (default handler re-raise) and the bash side maps watcher exit ≥128 to
   teardown + exit 130 regardless of trap delivery.
5. Default ports moved 8790/8791/5434 → **19790/19791/15434**, and the orphan
   reaper now requires the listener's argv to point into THIS checkout: a
   parallel fluidbox session on the same machine legitimately ran its own
   `fluidbox-server` with 8790 as its internal bind, which the first reaper
   version killed once (it respawned) and which then kept colliding with the
   demo's public port. Foreign listeners are now named-and-refused, never
   killed.
