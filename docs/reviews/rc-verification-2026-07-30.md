# Adversarial verification of the RC readiness report — `v0.4.0-rc.1`

**Date:** 2026-07-30
**Branch:** `release/prime-time-rc` @ `f59a6ec` (nothing pushed, tagged, merged; `main` untouched)
**Subject:** `docs/reviews/release-candidate-readiness.md`
**Mandate:** try to break that report's verdict. Treat its claims as hypotheses and
re-derive the load-bearing ones independently.

## Verdict

# DOWNGRADE

**From** `READY FOR CONTROLLED BETA`
**To** `READY FOR CONTROLLED BETA AFTER THREE NAMED FIXES` — listed in §8, all
small, none architectural.

> **UPDATE — the three fixes are applied.** See §11. All three were made and
> red-green verified after this report was first written; the guards are now
> **18** and **10** assertions and the false absolute is gone from all seven
> places it had propagated to. On the strength of that, **the verdict rises to
> `READY FOR CONTROLLED BETA`** — with the three P2 items in §11 still open and
> the pre-existing risks (no live Claude run, one platform, untouched supply
> chain) unchanged and still owned by the maintainer.

This is a downgrade of the *report*, not a repudiation of the work. The single
most important claim — that the P0 permission-gate bypass is closed and that
`scripts/gate-proof.sh` is real evidence rather than a harness that would pass
anyway — **survived the decisive mutation test and is CONFIRMED**. I built the
runner image, removed the `PreToolUse` hook, rebuilt, re-ran, and the suite
correctly collapsed. That was the question with the most damage attached and the
report got it right.

The downgrade rests on two things the report got wrong in the other direction:

1. **A security claims-matrix row states a false absolute.** `claims-matrix.md`
   C1 says the eval API port "**cannot be loopback-bound**", and §4.1 of the
   readiness report says a loopback publish "**breaks every run**". I measured
   the opposite on the exact platform the entire candidate was validated on,
   including on an isolated per-run network. The reasoning that justified
   leaving a port on `0.0.0.0` does not hold there.
2. **The guard written to stop BLK-04 recurring does not catch BLK-04
   recurring** in its most natural spelling. I reintroduced a working published
   admin credential and `compose-assertions.sh` reported 14/14 pass.

Both are the same species of defect the report is otherwise unusually good at
naming: an environment or an assertion wearing the costume of a result.

---

## Method, and the constraints honoured

Every hard constraint was respected and I verified it afterwards rather than
assuming it:

- Nothing pushed, tagged, merged; no PR. `main` untouched. Working tree clean at
  the end (`git status --porcelain` empty).
- The maintainer's dev stack ran throughout and was intact at the end:
  `deploy-postgres-1` and `deploy-litellm-1` still up, `deploy_fluidbox-pgdata`
  volume present.
- All database work used a throwaway `fluidbox_verify`, created and dropped by
  me. `DATABASE_URL` never pointed at `fluidbox`.
- Only artifacts I created were removed (`fluidbox-sandbox-runner:rcverify`,
  `:rcverify-mut`, a pulled `curlimages/curl`, three scratch directories under
  `$HOME`). No `docker system prune`, no `:dev` image touched, no volume removed.
- Clone under `$HOME`, never `/tmp` — and see §6, where I confirm *why* that
  matters.
- `DOCKER_HOST=unix://$HOME/.colima/default/docker.sock` on everything.
- **Live model spend this pass: $0.00.** I did not run a live Codex probe; the
  report's two runs already answer that question and re-running it would have
  bought a third data point on a claim I had no reason to doubt. Against the $5
  cap, actual spend was zero.

---

## 1. Is `gate-proof.sh` real evidence? — CONFIRMED

This was the most important question and the answer is yes.

### The decisive mutation

Baseline, against an image built from this worktree:

```
$ docker build -t fluidbox-sandbox-runner:rcverify -f images/sandbox-runner/Dockerfile images
$ GATEPROOF_IMAGE=fluidbox-sandbox-runner:rcverify scripts/gate-proof.sh
  RESULT: 14 passed, 0 failed
```

Then I removed the hook that is the entire fix — the one line that routes every
tool call through the gate — and rebuilt the real image:

```
$ python3 -c "…"   # delete: hooks: { PreToolUse: [{ hooks: [preToolUseGate] }] },
$ docker build -t fluidbox-sandbox-runner:rcverify-mut -f images/sandbox-runner/Dockerfile images
$ GATEPROOF_IMAGE=fluidbox-sandbox-runner:rcverify-mut scripts/gate-proof.sh
```

```
 A — deny everything, READ-ONLY-classified probe (the class that bypassed)
  ✗ the gate was NEVER consulted — the bypass is back
  ✗ the DENIED command executed anyway
      digest b360b5db3df4d24ff471d66ff543a8b69b02a40c6f340f2fa7393fb8ee8a7209
      of a nonce minted seconds ago came back in the tool_result
  RESULT: 12 passed, 2 failed
```

Script exit code on that run: **1**, verified separately.

This is the property that matters. Against an unfixed runner the suite fails,
and it fails on exactly the scenario that models the shipped bypass — a
read-only-classified `Bash` command reaching execution with `/permission` never
called. The harness is not green-by-construction.

### The digest witness is genuinely unfabricatable

I confirmed the mechanism rather than taking it on faith. The nonce is minted per
scenario by `openssl rand -hex 10` *after* the mock starts and is interpolated
into the command template; the assertion is whether the SHA-256 of that nonce
appears anywhere in the recorded HTTP traffic. In the fixed build it appears zero
times under `deny` and appears under `allow` (scenario D). In the mutated build
it appeared under `deny` — which is only possible if the command actually ran
inside the container and its output came back on turn 2. There is no cache, no
prior recording, and no path by which the mock could produce that digest without
the command executing. It is a sound witness.

### The positive controls really do gate the negatives

C (allow + mutating) and D (allow + read-only) both fired in every run, including
the mutated one. That is the correct behaviour: they are meant to prove the
harness *can* produce the effect, so an absence in A/B means the gate held rather
than that the rig was inert. The report's claim that C caught a real uid-mismatch
defect during development is consistent with the code — the `chmod 0777` on the
scenario workspace and the preflight both exist and both carry comments
explaining that exact failure.

### One real defect in the harness, found here

`permission_calls()` is wrong:

```sh
permission_calls() { grep -c '"kind": "permission"' "$SC_LOG" 2>/dev/null || echo 0; }
```

When there are zero matches, `grep -c` prints `0` **and exits non-zero**, so the
`|| echo 0` fires too and the function returns the two-line string `0\n0`. The
caller then does `[ "$(permission_calls)" -ge 1 ]`, which is a syntax error:

```
scripts/gate-proof.sh: line 183: [: 0
0: integer expected
```

Observed live during the mutated run. **It fails closed** — the erroring `[`
returns non-zero, so the `else` branch runs and the assertion is correctly
reported as a failure — so it did not corrupt my result. But it is latent: the
"gate WAS consulted (N call(s))" message would print a mangled count, and the
`attempts` arithmetic in scenario F rests on the same function, where a
`0`-attempt case would produce a misleading diagnostic rather than a clean one.
Fix: `grep -c … || true`, or `| wc -l`.

**Assessment: `gate-proof.sh` is real evidence.** The P0 closure is confirmed and
is now genuinely reproducible from the repository at zero cost, which was the
central improvement this candidate claims. I could not break it.

---

## 2. Do the three new guards catch what they claim? — PARTLY. Three new holes.

The report predicted a fourth hole was plausible and named the pattern: *an
assertion testing an identifier's presence, which a function's own declaration
satisfies*. That prediction was correct, and the pattern recurs **three** more
times — twice in `compose-assertions.sh` and once in `demo-selftest.sh`, the
latter in a check written during this same pass, two checks below a comment
explaining the trap.

### Positive controls first — the guards do catch the original defects

I reintroduced each defect the guards were written for:

| Reintroduced defect | Guard | Result |
|---|---|---|
| `${FLUIDBOX_ADMIN_TOKEN:-fluidbox-eval-only}` (the original BLK-04 shape) | compose-assertions | **13/1 — caught** |
| `- "5433:5432"` (quoted non-loopback publish) | compose-assertions | **13/1 — caught** |
| `SERVER_BIN="$(resolve_server_bin)"` (the fresh-clone stdout-capture bug) | demo-selftest | **8/1 — caught** |
| deleted the `resolve_docker_endpoint` call site | demo-selftest | **8/1 — caught** |
| deleted the tripwire's only call site | `gate.test.mjs` | **1 fail — caught** |
| deleted the tripwire declaration *and* its call site | `gate.test.mjs` | **2 fail — caught** |

The last two matter: the report's headline "new finding" was that the old suite
missed a deleted call site. The fix works, and it also survives the sneakier
version where you delete the declaration too so no dangling identifier remains.
That one is genuinely closed.

### HOLE 1 — a bare literal admin token is caught by nothing (reintroduces BLK-04)

The guard has two token checks. The first rejects the `:-` *shape*. The second
requires that `FLUIDBOX_ADMIN_TOKEN:?` appear **somewhere in the file** — and the
eval compose has two services that set the token (`server` at line 81, `web` at
line 112). So hardcoding the server's credential as a plain literal, leaving the
web service's `:?` untouched, satisfies both:

```sh
# server service only:
-  FLUIDBOX_ADMIN_TOKEN: "${FLUIDBOX_ADMIN_TOKEN:?required — …}"
+  FLUIDBOX_ADMIN_TOKEN: "fluidbox-eval-only"

$ bash deploy/compose-assertions.sh
compose-assertions.sh: 14 passed, 0 failed
```

**This is BLK-04 itself — a working, repository-published admin credential on the
API service — passing the guard that exists specifically to prevent it.** It is
not an exotic mutation; it is the most natural way someone "simplifies" that
noisy `:?` line. The `:-` check is a check on one *spelling* of the defect, not
on the defect.

Fix: assert per-service that the value is a `${…:?…}` substitution — e.g. parse
`docker compose config` output (already invoked in check 4) and assert the
rendered `FLUIDBOX_ADMIN_TOKEN` equals the injected sentinel for every service
that sets it, rather than grepping the source text.

### HOLE 2 — an unquoted published port evades the loopback check entirely

`published_ports()` matches only double-quoted entries:

```sh
grep -nE '^[[:space:]]*-[[:space:]]*"[^"]*:[0-9]+"' "$1"
```

Docker Compose accepts unquoted short-form ports. Adding `- 9999:9999` to the dev
file — a real all-interfaces publish — is invisible:

```sh
$ sed -i '' 's/    ports:/    ports:\n      - 9999:9999/' deploy/docker-compose.dev.yml   # first occurrence
$ bash deploy/compose-assertions.sh
compose-assertions.sh: 14 passed, 0 failed
```

The file still parses, `docker compose config` is happy, and the port is exposed
to the network segment. The guard's whole purpose — "everything else is
loopback" — is bypassed by omitting quotation marks.

Fix: read ports from `docker compose config` (which normalises both forms into a
structured `ports:` list with an explicit `host_ip`) instead of grepping YAML
source.

### HOLE 3 — the mount probe check is a bare presence assertion

`demo-selftest.sh` check 4:

```sh
if grep -q 'fluidbox-mount-probe' "$S" && grep -q 'cannot read files from this checkout' "$S"; then
```

Both strings survive if the probe is moved into a function that is never called.
I wrapped the probe block in `unused_mount_probe() { … }` — the demo no longer
probes anything, an unshared checkout would once again silently produce a
meaningless "successful" run — and:

```
$ bash scripts/demo-selftest.sh
demo-selftest.sh: 9 passed, 0 failed
```

This is precisely the trap the same file warns about **31 lines earlier**, in the
comment above check 3:

> *"Definition AND call. Testing only for the name is the same trap that let the
> gate suite stay green while the tripwire's only call site was deleted: a
> function's own declaration satisfies a presence check."*

Check 3 applies that lesson (defs/uses counting, which is why my P4 mutation was
caught). Check 4, written in the same commit, does not. The report's §4.3 defect
— the one it calls "the third instance of one pattern in this codebase" — is
guarded by an assertion that the pattern defeats.

Fix: the same defs-and-uses treatment check 3 already uses, or assert the probe
runs before the health-wait by checking call ordering.

### Assessment

The guards are real and they catch the specific defects that motivated them.
They are not yet *properties*; they are regression tests for particular
spellings. Two of the three are grep-over-YAML where a parsed document is
available in the same script. That is a fixable class of weakness, not a design
error — but the report's framing ("that is how a published credential survived
three releases", "9 assertions, red-green verified") reads as stronger coverage
than the guards deliver.

---

## 3. Is the BLK-04 reasoning right? — NO. It is false on the validated platform.

This is my strongest contradiction of the report.

### What the report claims

§4.1: *"Loopback-binding the API port **breaks every run**: the Docker provider
puts each sandbox on its own per-run network and reaches the control plane via
`host.docker.internal:host-gateway`, which resolves to the host gateway, not
`127.0.0.1`. A loopback publish makes the control plane unreachable from every
sandbox."*

`claims-matrix.md` C1 hardens this into an absolute: *"The API port is still
published on all interfaces and **cannot be loopback-bound**."*

### What I measured

A container publishing **only** on `127.0.0.1`, reached from a sibling container
over `host.docker.internal` — first on the default bridge, then on its own
isolated network, matching the per-run topology the argument invokes:

```
$ docker run -d --rm --name rcv-lo -p 127.0.0.1:18899:80 python:3.12-alpine \
    sh -c '… python3 -m http.server 80'
$ docker inspect rcv-lo --format '{{json .HostConfig.PortBindings}}'
{"80/tcp":[{"HostIp":"127.0.0.1","HostPort":"18899"}]}

from the macOS host                 : LOOPBACK-PUBLISH-REACHED
from a sibling container            : LOOPBACK-PUBLISH-REACHED
sibling on its OWN per-run network  : LOOPBACK-PUBLISH-REACHED
```

`host.docker.internal` resolves to `192.168.5.2` inside the VM. colima's
port-forwarding machinery makes a loopback-published port reachable at that
address. **The stated mechanism does not hold on colima**, which is the engine
every result in the candidate was produced on.

### Why the report reached the wrong conclusion

It conflates two different settings that happen to share the word "bind":

- `FLUIDBOX_BIND: 0.0.0.0:8787` — the **process's** listen interface inside the
  container. This is the CLAUDE.md gotcha, it is genuinely load-bearing, and it
  is **hardcoded** in the eval compose (line 77). It is not configurable and
  nobody proposed changing it.
- `FLUIDBOX_EVAL_API_BIND` — the **host-side interface of the docker port
  publish** (line 74). Entirely separate. Setting it to `127.0.0.1` does not
  touch what the server listens on.

The CLAUDE.md warning is about the first. The report applied it to the second.

### Honesty about the scope of my finding

I am not claiming the report's conclusion is wrong on every engine. On **native
Linux Docker**, `host.docker.internal:host-gateway` resolves to the bridge
gateway (e.g. `172.17.0.1`) and a `127.0.0.1`-published port would indeed be
unreachable there. The claim is **platform-dependent, and stated as universal**.

I also did not complete a full fluidbox run with `FLUIDBOX_EVAL_API_BIND=127.0.0.1`
— that needs the eval compose up, and a second `fluidbox-server` against this
daemon is the documented orphan-sweep footgun with the maintainer's stack
running. So: I have disproven the *mechanism* on the validated platform, not
executed the end-to-end run. That residual is real and I am naming it rather than
rounding it away.

### What follows

- The absolute in `claims-matrix.md` C1 must go. A security claims matrix whose
  stated purpose is *"a previous release shipped four sentences that a
  security-conscious adopter would rely on and that were measurably false"*
  cannot itself contain a measurably false sentence about a network exposure.
- The better fix the report dismissed is not obviously wrong. It concluded the
  port "stays published" because loopback breaks runs; on the validated platform
  it does not. The honest default for an eval profile shipped to twenty beta
  participants is `FLUIDBOX_EVAL_API_BIND` defaulting to `127.0.0.1`, documented
  as "set this to `0.0.0.0` if your engine needs it" — failing safe, with an
  escape hatch — rather than defaulting open with a paragraph of justification.
- The report's *other* BLK-04 remedy — making the token required — is genuinely
  correct, verified, and is the change that actually removes the credential. That
  part stands. (Though see Hole 1: the guard protecting it is porous.)

The report was right that BLK-04 bundles four things and that the credential is
the defect. It was wrong that the open port was forced.

---

## 4. Are the seed-policy dispositions defensible? — YES, with one premise
   correctly labelled unproven

**The deny list is defensible.** `Agent`, `Task`, `Workflow`, `Skill`,
`TaskCreate` all start execution whose nested calls are not guaranteed to surface
as top-level `tool_use` blocks. The gate binds by *routing*, and the routing
happens on top-level blocks; nested calls are outside that mechanism unless
proven otherwise.

**Is the premise testable?** Yes — and neither review tested it. It is testable
by exactly the harness that already exists: extend `gate-proof.sh` with a mock
returning a canned `Agent`/`Task` `tool_use`, and count `/permission` calls for
the tools the sub-agent then invokes. That is a bounded piece of work on
machinery already built, and it would convert A5 from "we refuse" to "we
mediate". I did not build it — it is a day's work, not a verification step — but
the report should not describe the question as intractable, because its own new
harness is the instrument for answering it.

**Usability cost is real but correctly traded.** Denying these five means an
agent cannot delegate. For a governed-sandbox product whose entire proposition is
that every call is decided before it runs, failing closed on the one class the
gate demonstrably cannot see is the right default. It is per-agent widenable by
an operator who has measured it. I would not overturn this.

**The `Task` finding is real and well-caught.** The previous seed allowed `Task`;
the pinned CLI names its subagent tool `Agent`; the allow-rule was inert only by
naming accident. Verified in the binary: the CLI ships `WorkflowTool`,
`MonitorTool` and an `Agent`-named subagent tool. A standing allow for a
sub-execution tool waiting on an upstream rename is a genuine latent bypass and
removing it was correct.

**I checked the allow list for anything that shouldn't be there.** The
allow-listed set is `Read, Glob, Grep, LS, TodoWrite, NotebookRead, ToolSearch,
EnterPlanMode, ExitPlanMode, AskUserQuestion, ReportFindings, Monitor, TaskGet,
TaskList, TaskOutput, CronList`. Fifteen of these are observational or
bookkeeping and are fine.

**`Monitor` is the one I would move.** I extracted its definition from the pinned
CLI binary in the runner image. It is not observational — it **runs bash**:

> *"Start a background monitor that streams events from a long-running script…
> Your script's stdout is the event stream… The script runs in the same shell
> environment as Bash."*
> *"To wait for a condition, use Monitor with an until-loop (e.g. `until <check>;
> do sleep 2; done`) — **Monitor runs bash**."*

It also accepts a `ws:` source that opens an outbound WebSocket to an arbitrary
URL — network egress, which this same policy denies for `WebFetch`/`WebSearch`/
`DesignSync` under "the sandbox has no business fetching the internet".

So `Monitor` is `allow`-listed while `Bash` — the same execution surface — goes
through prefix classification with a deny regex, and while every other egress
tool is denied outright. `tools.rs` groups it as `ToolGroup::Meta`, which is what
led to the misclassification. In the seed's own logic it belongs with `Bash`
(shell classification) or with the egress deny group, not in the observational
allow list.

This is a genuine gap in the "23 previously-ungoverned tools" work: the tools
were all *registered*, which is what the pinning test asserts, but at least one
was registered with the wrong disposition. The test can only check that a rule
exists, not that it is the right rule. I rate this **P2, pre-beta** — not a
bypass of the gate (the call is still decided; it is decided *allow*), but an
`allow` on a shell-executing, network-capable tool is not what the file's own
stated rationale would produce.

---

## 5. The headline numbers — CONFIRMED, including that the DB tests really connect

```
$ export DATABASE_URL=postgres://fluidbox:***@127.0.0.1:5433/fluidbox_verify
$ cargo test --workspace
17 suites, 857 passed, 0 failed
```

857 matches §6 exactly (§3.1's 856 predates the new test, as the report says).

**The DB tests genuinely connect rather than self-skipping.** Two independent
proofs:

```
$ docker exec deploy-postgres-1 psql -U fluidbox -d fluidbox_verify -tAc \
    "select count(*) from information_schema.tables where table_schema='public';
     select max(version) from _sqlx_migrations;"
44
26
```

and the negative control — the same suite with the variable unset:

```
$ cargo test -p fluidbox-db                      # DATABASE_URL set
test result: ok. 138 passed
$ env -u DATABASE_URL cargo test -p fluidbox-db  # unset
test result: ok. 0 passed
```

138 → 0. The self-skip is real, and it did not happen. This is the check the
report claimed and it holds.

Other suites reproduced: `node --test images/runner-lib/*.test.mjs` 21 passed / 2
skipped (the two Linux-only entrypoint assertions, as documented — they execute
in CI, not here); replay runner 8 passed; `version-check.sh` PASS with all sites
at `0.4.0-rc.1` including the release-please manifest.

---

## 6. Fresh-clone first run — CONFIRMED, and the 0-byte-diff trap is real

Cloned to `$HOME` (never `/tmp`, per the constraint — and see below), no `.env`,
no `target/`:

```
$ git clone <worktree> ~/fbx-rcverify-clone && cd ~/fbx-rcverify-clone && just demo
```

Two commands, exit 0, **73s total wall clock** including the cold control-plane
compile. The diff is real, not empty:

```
-  return "Hello, name!";
+  return "Hello, " + name + "!";
… new file deploy.log
```

Security receipt: **5 tool calls decided server-side before execution** — 3
policy-allow, 1 policy-deny, 1 human-allow after an approval pause on
`Bash «./deploy.sh»`. `$0.00`, 0 model requests. Teardown complete; the
maintainer's stack untouched.

The report's ~70s figure is accurate (I measured 73s on a warm cargo registry).

**The `/tmp` claim is itself verified as a real hazard.** The constraint I was
given — that a `/tmp` checkout bind-mounts as an empty directory under colima and
produces a demo that "succeeds" while proving nothing — is exactly the defect the
report found and fixed. I did not re-trigger it (I had no reason to spend a run
proving a hazard I was told to avoid), but the fix is present and exercised: the
demo writes `fluidbox-mount-probe` into the data dir and reads it back from
inside a container before the control plane starts. That code path ran in my
clone. Caveat: per Hole 3 above, the *guard* on that fix is defeatable, though
the fix itself works.

---

## 7. The unexplained `awaiting_approval` hang — did not reproduce

The report describes one hang at `awaiting_approval` after the verdict was
written, with the sandbox container gone from `docker ps -a`, non-reproducing,
attributed tentatively to three `fluidbox-server` processes on one daemon.

My fresh-clone run — executed with the maintainer's stack running, i.e. under
real contention, though with only one `fluidbox-server` — completed cleanly at
the approval pause and resumed. **One additional non-reproduction.** That is a
data point, not an explanation, and I did not hunt it systematically: chasing a
one-shot hang with an unknown trigger is not a good use of a verification pass,
and the report's own handling of it (neither calling it a defect nor pretending
it did not happen) is the right posture.

The mechanism it proposes is plausible and documented — the boot orphan sweep
reaps containers whose session is absent from *its* database, which is exactly
what "container vanished, nothing in the log" looks like. I would leave it as the
report has it: an open question a twenty-person beta is a reasonable instrument
for. I would add one thing: the demo could detect it cheaply, since a session
sitting in `awaiting_approval` with a decided approval and no live container is a
server-side detectable state.

---

## 8. Upgrade and rollback — CONFIRMED exactly

Reproduced the compile-time-migration-set technique independently, in a separate
target directory so the maintainer's build was untouched:

```
$ rm migrations/0026_policy_versions.sql && touch crates/fluidbox-db/src/lib.rs
$ CARGO_TARGET_DIR=$HOME/fbx-rcverify-target cargo build -p fluidbox-server
```

**Rollback** — the 25-migration binary against a 26-migration database:

```
Error: migration 26 was previously applied but is missing in the resolved migrations
```

Byte-identical to the report's quoted message. Refuses loudly, does not proceed.

**Upgrade** — restored `0026`, rebuilt, pointed the candidate binary at a
database left at 25:

```
$ psql -tAc 'select max(version) from _sqlx_migrations'
25       # after the pre-0026 binary
26       # after the candidate binary
```

Both directions confirmed. The CHANGELOG's "no binary rollback past `0026`, and
it fails loudly rather than silently" is verified, as the report says.

One thing I can add: the report's disclosed "harness artifact" (a v0.3.0-*shaped*
binary failing to seed with `null value in column "yaml_source"`) is correctly
diagnosed. It is current seeding code compiled against a pre-`0026` schema, not a
v0.3.0 defect, and it does not affect the upgrade result.

---

## 9. The rewritten prose — mostly disciplined, with the one false absolute

I read `claims-matrix.md`, `compatibility-matrix.md`, and the readiness report
looking for both overstatement and overcorrection.

**The prose is unusually honest and I found little to attack.** The
evidence-class taxonomy (PROVEN / PROVEN-NOT-GATED / PARTIAL / INFERRED / NOT
CLAIMED) is real work, and rows are placed conservatively:

- B6 says the "no egress" claim is **FALSE on the Docker default** and names
  `HostDev` as the culprit. Correct, matches the code, and is a claim against
  interest.
- A5 says nested gating is **NOT CLAIMED** — "the honest status is that we refuse
  rather than that we mediate". Exactly right.
- A6 says an old pinned runner image is **NOT CLAIMED — and not detected**.
- D1–D3 say signing, SBOM, provenance, reproducibility and CVE monitoring **do
  not exist**. I verified: `npm install` (not `npm ci`) in both
  `images/sandbox-runner/Dockerfile:17` and `images/codex-runner/Dockerfile:30`,
  no lockfile in either runner directory, and `.github/dependabot.yml` covers
  `/`, `/apps/web`, `/` — no runner directories. **The supply-chain section
  fabricates nothing and understates nothing.**
- E2 says a live Claude run is **NOT VALIDATED** and explicitly refuses to let
  the gate proof substitute for it.

**The one defect: `claims-matrix.md` C1's "cannot be loopback-bound"** (§3). In a
document whose stated reason for existing is that a prior release shipped
sentences a security-conscious adopter would rely on and that were measurably
false, that is the one sentence that must not be there.

**Minor overstatement, worth a word change.** A2 is graded **PROVEN** with the
evidence "14 assertions, CI on every PR". The gate proof does prove routing on
the Claude harness for the classes it probes — but the qualifier that belongs
next to it lives only in the document's header note ("routing is not a control
against a workload already executing arbitrary code, and an older pinned
`runner_image` routes nothing"). A2's own cell says "every tool call is routed",
and the nested-call carve-out is in A5, two rows down. A reader scanning the
matrix for the headline security property gets an unqualified PROVEN. I would
add "for top-level tool calls; see A5" inline.

**No overcorrection found.** I looked for the opposite failure — hedging a
property that is actually solid into uselessness — and did not find it. B1 (no
upstream credential in a sandbox) is called "the strongest property in the
product" and that is defensible.

---

## 10. Does the beta package fabricate anything? — NO

Ten files, 1,383 lines. I checked for invented metrics, fake participant data,
and claims stronger than the candidate supports.

- `metrics-scorecard.md` is a **blank instrument**: every value is `___` or `—`,
  with explicit arithmetic for each of the eight thresholds. It states outright
  that *"a fabricated value is worse than a missing one because it silently moves
  a threshold"* and that unmeasured values are excluded from denominators. There
  is no fabricated data anywhere in it.
- `invitation-draft.md` and `participant-guide.md` describe the product as
  deciding "every tool call against a policy before it runs". Given §4 (nested
  sub-execution is denied, not mediated) and the old-runner-image residual, this
  is the same slight overstatement as A2 — defensible for participant-facing
  copy about the default configuration, but it is the sentence the film clips
  were held back for. I would apply the same "top-level tool calls" qualifier the
  claims matrix uses.
- The participant guide correctly leads with the deterministic replay, labels it
  as making no model calls, and warns about the Rust toolchain / cold registry
  assumption behind the time-to-first-demo threshold.

The package is honest. The one wording issue is inherited from A2, not invented
here.

---

## Judgment calls I was asked to adjudicate

### `.release-please-manifest.json` → `0.4.0-rc.1`

**Do not move it. Revert that one line.**

The manifest is release-please's memory of *the last released version*. Nothing
has been released. Setting it to `0.4.0-rc.1` records a release that does not
exist, and if the RC is never published — a live possibility, given the report's
own §7 risk list — the manifest permanently disagrees with reality.

The report frames this as a coin-flip because `version-check.sh` asserts the
manifest equals canonical, so "the two cannot disagree". That constraint is the
tail wagging the dog: the guard was written to catch stale version *sites*, and
the manifest is not a version site — it is state owned by a tool with different
semantics. The right fix is to exclude the manifest from `version-check.sh`, or
to compare it against *the last tag* rather than against canonical.

Publishing by `workflow_dispatch` (which is the documented path anyway) works
either way. Reverting is the lower-consequence option and is reversible; a wrong
manifest that release-please later reasons from is not.

### `0.4.0-rc.1` as the version

**Correct.** Minor rather than patch is right: pre-1.0 with `bump-minor-pre-major`,
and the candidate carries an operator-visible action (the seed policy does not
re-apply to existing deployments — import it or every supervised run pauses). A
patch bump would understate that. The `-rc.1` prerelease is right for something
with an unvalidated live-Claude path. The version-guard change that made
prereleases expressible is a genuine prerequisite and it works (15 sites agree).

### Shipping an RC with an untouched supply chain

**Acceptable for a twenty-person private beta. Not acceptable for a public
`v0.4.0`.**

The distinguishing fact is the threat model of the audience. Twenty invited
participants installing from a tagged artifact, told in writing that nothing is
signed and no SBOM exists, are making an informed choice. The report does tell
them: D1–D3 are unambiguous and the compatibility matrix carries the
artifact-verifiability table. That is the mitigation that makes it defensible.

The reason it must not carry into a public release is stated well in the report
itself: *"For a product whose promise is containment and accountability, the code
that runs beside the workspace is the least verifiable thing it ships."* The
runner image is the component with the most privileged position relative to
untrusted work, and it is built with `npm install` against no lockfile, so two
builds of the same tag can differ. The report's own evidence that drift was not
*observed* over one week is not evidence that it cannot happen.

Concretely for the beta: I would add lockfiles and switch to `npm ci` before
inviting anyone — that is an afternoon, it is the highest-value item on the
supply-chain list, and it makes every subsequent claim about the runner image
mean something. Signing, SBOM and provenance can follow before `v0.4.0` proper.

---

## Contradictions of the report, in both directions

**Where I contradict it (report was too generous to itself):**

1. `claims-matrix.md` C1 "cannot be loopback-bound" and readiness §4.1 "breaks
   every run" are **false on the validated platform**. Measured three ways
   including on an isolated per-run network. (§3)
2. `compose-assertions.sh` does **not** catch a bare literal admin-token default —
   i.e. it does not catch BLK-04 recurring. 14/14 green with the credential back.
   (§2, Hole 1)
3. `compose-assertions.sh` does **not** catch an unquoted non-loopback port
   publish. 14/14 green. (§2, Hole 2)
4. `demo-selftest.sh` check 4 is a bare presence assertion; the mount probe can
   be made unreachable with the suite still 9/9. This is the exact trap the same
   file warns about 31 lines earlier. (§2, Hole 3)
5. `gate-proof.sh`'s `permission_calls()` returns `"0\n0"` on zero matches and
   throws `[: integer expected`. Fails closed, but the diagnostics are corrupt.
   (§1)
6. `Monitor` is `allow`-listed but runs bash and can open outbound WebSockets —
   verified from the pinned CLI binary. The "23 tools now governed" work
   registered it with a disposition its own rationale contradicts. (§4)
7. A2's PROVEN cell omits the top-level-only qualifier that lives two rows away
   in A5. (§9)

**Where I confirm it, including against my own attempts to break it:**

1. **`gate-proof.sh` is real evidence.** The decisive mutation collapses it.
   Positive controls fire. The digest witness is sound. This is the claim with
   the most riding on it and it is solid. (§1)
2. The `gate.test.mjs` tripwire fix is genuine and survives the sneakier
   declaration-plus-call-site deletion. (§2)
3. **857 tests, and the DB tests really connect** — 138 → 0 with `DATABASE_URL`
   unset; 44 tables at migration 26 in the throwaway. (§5)
4. Fresh-clone first run works in 2 commands / 73s with a real diff and 5
   server-side decisions. Not a 0-byte-diff phantom. (§6)
5. Upgrade and rollback reproduce exactly, including the verbatim refusal
   message. (§8)
6. The supply-chain disclosures are accurate and complete — verified against the
   Dockerfiles and `dependabot.yml`. (§9)
7. The beta package fabricates no data; the scorecard is a blank instrument with
   an explicit anti-fabrication rule. (§10)
8. The seed policy's sub-execution deny is the right call, and the latent `Task`
   allow-rule was a real find. (§4)
9. The report's self-critical passages are accurate, not performative — the YAML
   quoting lesson, the positive-controls argument, and the "environment problem
   wearing the costume of a result" pattern are all things I independently
   confirmed while trying to break them.

---

## The three fixes that justify the downgrade

Small, all of them, and none architectural:

1. **Delete the false absolute.** `claims-matrix.md` C1 must stop saying the API
   port "cannot be loopback-bound", and readiness §4.1 must stop saying loopback
   "breaks every run". Replace with the platform-dependent truth. Then reconsider
   defaulting `FLUIDBOX_EVAL_API_BIND` to `127.0.0.1` with a documented override,
   which fails safe.
2. **Close Hole 1.** Assert the rendered admin token per service from
   `docker compose config`, not the source spelling. As it stands, the guard
   against the launch-blocking defect does not catch the launch-blocking defect.
3. **Close Hole 3.** Give `demo-selftest.sh` check 4 the defs-and-uses treatment
   check 3 already has.

Hole 2, the `permission_calls()` bug, and the `Monitor` disposition are P2 — I
would fix them in the same sitting, but they do not gate the beta.

With those three done I would sign off on `READY FOR CONTROLLED BETA` as written.
Without them, the candidate ships a security claims matrix containing a false
statement about a network exposure, and two guards that do not guard.

---

## What I did not test, and why

Stated plainly, because an unexamined area reported as silence is the failure
mode this whole exercise exists to prevent.

- **No live Claude run.** The key is out of credit; the report already
  established this and it is its own top risk.
- **No live Codex run.** $0.00 spent. The report's two runs answer the question
  and I had no reason to doubt them; a third data point was not worth the tokens
  or the time.
- **No end-to-end run with `FLUIDBOX_EVAL_API_BIND=127.0.0.1`.** I disproved the
  mechanism, not the outcome. Bringing up the eval compose means a second
  `fluidbox-server` on this daemon, which is the documented orphan-sweep footgun
  with the maintainer's stack live.
- **No Kubernetes or EKS.** Forbidden by the mandate; no cloud resources created.
- **No `just e2e`.** Live-agent phases need credits, and issue #100 records four
  pre-existing red phases, so the result would not be attributable to this
  candidate.
- **No systematic hunt for the `awaiting_approval` hang.** One additional
  non-reproduction, honestly labelled as such.
- **No nested-sub-execution routing test.** I identified that `gate-proof.sh` is
  the right instrument for it and that it is tractable, but building it is
  development work, not verification.
- **Single platform.** macOS 15.6 arm64 / colima Linux arm64 / Docker 29.5.2 —
  the same single platform as the report, so my pass inherits that limitation
  rather than relieving it. Notably, finding §3 is *itself* platform-specific,
  which is a live illustration of why the compatibility matrix's insistence on
  VALIDATED-vs-EXPECTED is the right discipline.

---

## 11. The three fixes, applied and verified

Done in the commit following this report. Each was red-green verified: the guard
passes on correct code, and fails on the exact mutation that previously slipped
through.

### Fix 1 — the false absolute is gone (blocker 1)

It had propagated to **seven** places, which is the argument for treating a
claims matrix as load-bearing text rather than commentary: the error was written
once in a compose comment and copied into both user-facing security documents.

| File | Was | Now |
|---|---|---|
| `deploy/docker-compose.eval.yml` | "The API port CANNOT be moved to loopback… every run fails during provisioning" | The `FLUIDBOX_BIND` vs `FLUIDBOX_EVAL_API_BIND` distinction spelled out, with per-engine measured/expected status |
| `README.md` | "published on all interfaces **and cannot be loopback-bound**" | "published on all interfaces **by default**", plus how to narrow it and what to verify after |
| `SECURITY.md` | "a loopback publish would break every run" | engine-dependent, with the measured/expected split |
| `docs/release/claims-matrix.md` | C1 asserted the absolute | C1 corrected; **new row C1a** carries the engine-dependent claim at its true evidence class |
| `docs/release/upgrade-and-rollback.md` | "**cannot** be loopback-bound… breaks every run" | narrowing is engine-dependent, verify a run afterwards |
| `deploy/compose-assertions.sh` | comment repeated it; assertion text said "cannot be loopback" | comment states the trade-off; assertion renamed to "explains the trade-off behind its non-loopback **default**" |
| `docs/reviews/release-candidate-readiness.md` §4.1 | the original claim | dated **CORRECTION** block quoting what it said and why it was wrong |

The house convention for amending a claim (visible dated correction, not a silent
rewrite — as `CLAUDE.md` does for the OAuth confirmation claim) is followed
throughout.

**What I deliberately did NOT do: flip the default to `127.0.0.1`.** My own §3
recommended "reconsider" it, and on reflection the evidence does not support
changing a shipped default. I measured the *network path* on one engine; I never
completed an end-to-end fluidbox run with the loopback bind, and on native Linux
Docker the narrowing is expected to break. Flipping a default on a mechanism test
alone would be the same overreach this pass exists to catch. The exposure is now
accurately described and one environment variable away from being closed, which
is the honest state.

### Fix 2 — the admin-token guard now tests the property (blocker 2, Hole 1)

Two layers replace the single file-wide `grep -q 'FLUIDBOX_ADMIN_TOKEN:?'`:

- **Per-occurrence, source-level** (no docker needed): every non-comment
  `FLUIDBOX_ADMIN_TOKEN:` assignment in all three files must be a
  `${FLUIDBOX_ADMIN_TOKEN:?…}` substitution. The old check asked "does the
  required form appear *anywhere*", which the `web` service satisfied while
  `server` held a literal.
- **Rendered-document** (docker): with a sentinel injected, every rendered
  `FLUIDBOX_ADMIN_TOKEN` value must equal that sentinel. A literal cannot survive
  this whatever its spelling, because a literal does not change when the
  environment does.

Red-green — the mutation that previously passed 14/14:

```
FLUIDBOX_ADMIN_TOKEN: "fluidbox-eval-only"     # server service

  FAIL  …eval.yml has an admin-token assignment that is not a required substitution
  FAIL  …eval.yml renders an admin token the operator did not supply
compose-assertions.sh: 16 passed, 2 failed
```

Unmutated: **18 passed, 0 failed**. Both original defect shapes (`:-` default,
quoted `0.0.0.0` publish) still caught — the `:-` default now trips both layers.

### Fix 3 — the mount-probe check has teeth (blocker 3, Hole 3)

Two grep-for-a-string assertions became three real properties: the probe must
**exist**, be **reachable**, and be **ordered** before the control-plane launch.

Reachability uses the defs-and-uses form check 3 already had, generalised so it
works for a function invoked from a `case` arm (`up) demo_up ;;`), where the name
is neither at line start nor the first word after the indent. Definitions and
calls are told apart by what *follows* the name: `(` in a definition, anything
else in a call.

Red-green on both new properties:

```
probe wrapped in a never-called function:
  FAIL  the bind-mount probe is unreachable — it sits in unused_mount_probe (defs=1 calls=0)
probe moved after the control-plane launch:
  FAIL  the bind-mount probe does not precede the control-plane launch
```

Unmutated: **10 passed, 0 failed**; both original defects still caught.

**A note on getting this wrong first.** My initial version failed the *unmutated*
file: I assumed the definition line would match the call-regex and set the
threshold to `>1`, but `demo_up(` is followed by an open paren and never matched.
That is the same error class as the bug being fixed — asserting a pattern's
behaviour instead of measuring it — and it is why green-verification matters as
much as red. A guard that cries wolf on correct code gets deleted, which is
strictly worse than no guard. This is the third time that exact trap has been hit
in this file's history; it is recorded here so the fourth is cheaper.

### Verification after the fixes

```
compose-assertions.sh       18 passed, 0 failed
demo-selftest.sh            10 passed, 0 failed
gate-proof.sh               14 passed, 0 failed   (unchanged — not touched)
docker compose config       all three files parse
bash -n                     both guards parse
```

No Rust, no policy, and no runner source was modified, so the 857-test baseline
and the gate proof are unaffected by these fixes.

### Still open — the P2 items, deliberately not fixed here

Named so they are not mistaken for closed:

1. **`compose-assertions.sh` misses an unquoted port publish** (Hole 2). Its
   `published_ports()` regex requires double quotes; `- 9999:9999` is a real
   all-interfaces publish and is invisible. The fix is to read ports from
   `docker compose config`, which normalises both forms with an explicit
   `host_ip`. Left alone because it reworks the loopback logic, and reworking a
   guard is how guards acquire holes.
2. **`gate-proof.sh`'s `permission_calls()` returns `"0\n0"`** and throws
   `[: integer expected`. Fails closed; diagnostics corrupt. One-line fix
   (`|| true`, or `| wc -l`) — untouched here because the gate proof is the one
   artifact whose behaviour I would not want changed in the same commit that
   claims it still passes.
3. **`Monitor` is `allow`-listed but runs bash and opens outbound WebSockets.**
   A policy-content decision for the maintainer, not a guard defect: the pinning
   test can only assert a rule exists, not that it is the right rule.
