# Release-candidate readiness — `v0.4.0-rc.1`

**Date:** 2026-07-30
**Branch:** `release/prime-time-rc` (based on the four-worktree integration at `2e57b5c`)
**Mandate:** independently verify the integration evidence; if it holds, prepare a publishable release candidate and a 20-person private beta. Nothing pushed, tagged, published, or merged; no PR opened; `main` untouched; no cloud resources created; live-model spend capped at $10.

## Verdict

# READY FOR CONTROLLED BETA

Not `NOT READY`: the three changes the integration review named as the conversion from LIMITED BETA to release candidate are made, the P0 is closed and now provable from the repository at zero cost, and every check the project defines is green. Not `RC READY TO PUBLISH`: **no live Claude run was possible** (the key is out of credit), one platform and one architecture were validated, and the supply chain is unchanged — signing, SBOM, provenance, checksums and reproducible runner images all still absent. Those are not defects I can fix by testing harder; two of them need a funded key and a Linux/amd64 machine, and one needs a deliberate decision about release infrastructure.

The branch is in a state where **a maintainer can review one branch, publish the RC, and invite twenty real beta participants** — which was the stopping condition. What they cannot yet do is claim the candidate works with a live Claude model, because nobody has seen it.

---

## 1. Gate decision — was I allowed to package a release at all?

The mandate set four stop conditions. Each was checked independently before any packaging work began.

| Stop condition | Finding | Verdict |
|---|---|---|
| Integration verdict is NO-GO | The verdict is **LIMITED BETA** (`overnight-integration-review.md` §11) | not triggered |
| Any P0 remains | **None open.** Verified independently, not accepted: the fix is present in source as an *unscoped* `PreToolUse` hook (no matcher ⇒ every tool), an I/O-free `forceGateDecision()`, and a `GateWitness` tripwire that aborts without posting `/result`. I then reproduced the review's mutation matrix myself and extended it | not triggered |
| AWS teardown uncertain | **Certain.** Read-only audit: 0 EKS clusters in us-east-1/us-west-2/eu-west-1/ap-south-1; both validation VPCs `InvalidVpcID.NotFound`; 0 resources tagged `fluidbox-ephemeral=true`; 0 instances, 0 volumes, 0 unattached EIPs, 0 `eks-cluster-sg-*`; 0 CFN stacks matching `fbx-netadm`/`fluidbox`. The one surviving NAT gateway is `forceplatforms-regional-nat`, the unrelated pre-existing project the review attributed it to | not triggered |
| Branch lacks reproducible evidence for its central security claim | **Partially true, and this is the most important finding of the pass** — see §2 | addressed, not triggered |

### Branch state, verified rather than assumed

The worktree was clean at `2e57b5c`, 15 commits on `9515069`. All four source worktrees were still at the SHAs the review recorded. I compared each cherry-pick to its source by `git patch-id --stable`: **11 of 12 byte-identical**. The twelfth (`a40639b` ← `86483b3`) differs *only* in `.gitignore` context — both real files (`images/replay-runner/Dockerfile`, `justfile`) hash identically — so the one documented conflict resolution was faithful and nothing rode in on it. `.demo/` is correctly ignored; the `data-gate/` P3 stray was still present and is now removed.

## 2. The evidence gap I found, and closed

The review's most decisive evidence — the A1/B1 matrix showing a read-only-classified `Bash` command executing on unfixed `main` with **zero** gate consultations, and not executing on the fixed branch — was produced by a harness in `$CLAUDE_JOB_DIR/tmp/gateproof/`. **That directory no longer exists.** `CLAUDE_JOB_DIR` is unset; the harness is gone.

So the branch's strongest claim rested on evidence nobody could re-run. What remained in-repo was real but weaker: `gate.test.mjs` proves the hook is *wired* (it cannot prove the SDK *invokes* it), and `e2e-tool-gate.sh` phase 1 — the one that would prove it — **self-skips without model credits**, which is exactly the state the repository was in when the bypass shipped.

I rebuilt that harness **in the repository** as `scripts/gate-proof.sh`, and wired it into CI on every pull request.

It points the real runner image at a mock upstream returning a canned `tool_use` and a mock control plane whose verdict each scenario chooses. Real image, real entrypoint (so the production unlinked-fd credential hand-off runs), real `index.mjs`, real pinned CLI. **14 assertions, no API key, no model spend.**

```
== the gate proof — no API key, no model spend ==
  image: fluidbox-sandbox-runner:rc
  ✓ preflight: the container can write the bind-mounted workspace
  ✓ preflight: host.docker.internal resolves inside the sandbox

 A — deny everything, READ-ONLY-classified probe (the class that bypassed)
  ✓ the gate WAS consulted (1 call(s)) — this is the fix
  ✓ the denied command did NOT execute (its digest is absent from every turn)
 B — deny everything, MUTATING probe (host-visible side effect)
  ✓ no side effect in the bind-mounted workspace
  ✓ the gate was consulted for the mutating probe
 C — allow, MUTATING probe (POSITIVE CONTROL)
  ✓ the allowed command DID execute — the harness can produce the side effect
 D — allow, READ-ONLY probe (POSITIVE CONTROL for the digest witness)
  ✓ the allowed read-only command executed and its digest came back
 E — approval PRECEDES execution (verdict held open 6s)
    requested 1785390465370 · answered 1785390471380 (+6010ms held) · written 1785390471417 (+37ms after the verdict)
  ✓ the side effect appeared only AFTER the verdict — nothing ran while pending
 F — the gate fails CLOSED on every broken answer
  ✓ http500 → blocked indefinitely, still retrying after 25s (5 attempts), never executed
  ✓ unauth401 → no execution (runner exit 0, 1 attempt(s))
  ✓ wrongaud403 → no execution (runner exit 3, 1 attempt(s))
  ✓ nonjson → no execution (runner exit 0, 1 attempt(s))
  ✓ emptyjson → no execution (runner exit 0, 1 attempt(s))

  RESULT: 14 passed, 0 failed
```

**The witness is cryptographic, not circumstantial.** Under `allow`, the digest the runner returned for a nonce minted seconds earlier was `52f51dd6c3c582f38ef576c3af68e4b64a59b8033f0c109bb54f132874dc82f5`, byte-identical to the host-computed digest of that nonce. Under `deny`, the digest of that scenario's nonce appears **zero times** in the entire recorded traffic. Neither could be guessed, cached, or fabricated.

Three design points that make it trustworthy rather than merely green:

- **The positive controls are load-bearing.** Every denial assertion is an *absence*, and an absence has two explanations: the gate held, or the harness could never have produced the effect. C and D are what make B and A mean something. C caught a real harness defect during development (a uid-mismatch on the bind mount) that would otherwise have produced a clean sweep of green negatives and a completely false conclusion.
- **A preflight proves the mount before any scenario**, so an environment problem is reported as one rather than as a security result.
- **The wait is bounded because one behaviour under test is unbounded on purpose.** On a 5xx the runner retries `/permission` forever rather than assuming a verdict, so that container never exits. "Still retrying at the deadline, having executed nothing" is the pass — and discovering that is what made the first full run hang.

`wrongaud403 → exit 3` is worth noting: the runner *aborts* rather than converting a credential fault into a governance verdict.

## 3. Independent verification of the inherited claims

### 3.1 The test baseline reproduced exactly

Run from this worktree with `DATABASE_URL` on a throwaway database (`fluidbox_rcverify`), never the dev database:

| Check | Result | Time |
|---|---|---|
| `cargo fmt --all --check` | clean | 0s |
| `cargo clippy --workspace --all-targets -- -D warnings` | clean | 45s |
| `cargo test --workspace` | **856 passed, 0 failed**, 17 suites | 78s |
| `node --test images/runner-lib/*.test.mjs` | 20 passed, 0 failed | 1s |
| `node --test images/replay-runner/runner/test/*.test.mjs` | 8 passed, 0 failed | 1s |
| `helm lint deploy/helm/fluidbox` | clean | 0s |
| `pnpm install --frozen-lockfile && pnpm build` | exit 0 | 11s |

The DB tests genuinely connected rather than self-skipping: the throwaway database came out with 44 tables at migration 26, and the maintainer's `fluidbox` database was verified unchanged.

### 3.2 The mutation matrix — reproduced, and extended

The review claimed it closed two mutations that previously passed 12/12. I re-ran that and probed further:

| Mutation | Result | Note |
|---|---|---|
| unmutated | 14 pass / 0 fail | |
| `preToolUseGate = async () => ({})` | 13 / **1 fail** | caught — matches the review |
| hook scoped with `matcher: "Write"` | 13 / **1 fail** | caught — matches the review |
| hook deleted entirely | 13 / **1 fail** | caught |
| `permissionMode: "bypassPermissions"` | 13 / **1 fail** | caught |
| `forceGateDecision` answers `allow` not `ask` | 13 / **1 fail** | caught |
| `GateWitness.ungovernedResult` always `null` | 13 / **1 fail** | caught |
| **tripwire's only CALL SITE deleted** | **14 / 0 — NOT caught** | **new finding** |

The last one is a genuine hole the review missed. The suite asserted `/abortUngoverned\(/` appears in the runner source — which the function's **own declaration** satisfies. So the second layer of the gate could be removed entirely and the suite stayed green. Closed by a test that requires a declaration *and* a call, red-green verified. The same trap then appeared in my own new self-test and was fixed there too.

### 3.3 The demo and its receipts

Reproduced independently from a fresh clone (§5). The gate is genuinely real: server-authored verdicts (`source=policy` / `source=human`), a deny that provably suppresses the side effect, and a real diff.

## 4. Defects found and fixed in this pass

Seven, of which three were release-blocking and would have shipped.

| # | Defect | Severity | How found |
|---|---|---|---|
| 1 | **The eval quickstart shipped a working admin credential.** `FLUIDBOX_ADMIN_TOKEN` defaulted to `fluidbox-eval-only`, published in this repository, on an API port open to the network segment, beside a mounted Docker socket, with an unconstrained operator `local_copy` | **P1, launch-blocking** | inherited (BLK-04), verified verbatim |
| 2 | **`just demo` was broken on every fresh clone** — the from-source path, i.e. the path every new user takes | **P1, launch-blocking** | running it in a fresh clone |
| 3 | **`version-check.sh` could not express a prerelease**, so `just check` and the CI version gate failed on any `-rc` version | **release-blocking for an RC** | attempting the version bump |
| 4 | 23 of 30 advertised tools had no policy rule, so the gate fix would pause every supervised run | **P1** | inherited (§3.5b), plus a latent `Task` allow-rule the reviews missed |
| 5 | `just demo` exited 0 with a success-shaped receipt on a failed run | **P1** | inherited, reproduced |
| 6 | The demo's preflight validated a different Docker daemon than the server used | **P1** | inherited as a follow-up |
| 7 | **An unshared checkout silently produced a meaningless "successful" demo** | **P2, new** | the fresh-clone run under `/tmp` |

### 4.1 The eval quickstart (BLK-04) — and why the obvious fix was wrong

The review called this "one line plus a token default". It is not. Loopback-binding the API port **breaks every run**: the Docker provider puts each sandbox on its **own per-run network** and reaches the control plane via `host.docker.internal:host-gateway`, which resolves to the host gateway, not `127.0.0.1`. A loopback publish makes the control plane unreachable from every sandbox.

BLK-04 bundles four things — an open port, a published credential, a mounted socket, an unconstrained `local_copy` — and only one is the defect. The fix removes the **credential**: `FLUIDBOX_ADMIN_TOKEN` is now required (`:?`), so compose refuses to start. The dashboard, which nothing in a container needs, moved to loopback. The API port stays published, is now bind-configurable via `FLUIDBOX_EVAL_API_BIND`, and the residual is stated in the file and the README instead of implied away.

Verified operationally:

```
no token   -> exit 1: required variable FLUIDBOX_ADMIN_TOKEN is missing a value:
              required — the published default was removed because it granted anyone
              on your network full admin authority. Generate one with 'openssl rand -hex 32'
with token -> exit 0;  API host_ip 0.0.0.0 (documented) · dashboard host_ip 127.0.0.1
```

`deploy/compose-assertions.sh` guards it — **14 assertions**, red-green verified. Nothing guarded the compose files before: the Helm chart had `chart-assertions.sh`, and `docker-compose.eval.yml` was referenced by no job, script or recipe at all. That is how a published credential survived three releases.

**A lesson worth recording.** My first version of that guard passed 10/10 on a file that had **stopped being valid YAML** — my `:?` message contained `": "`, which in an unquoted scalar is a mapping. Every grep-based assertion passed because a grep never parses the document. The guard now runs `docker compose config` on all three compose files and separately asserts the required-variable form refuses an *empty* token, not only an unset one.

### 4.2 `just demo` was broken on every fresh clone

Found by doing the thing none of the previous validation did: cloning into an empty directory and running the documented command.

`server_bin()` returned the binary path by `echo`ing it and was called as `BIN=$(server_bin)`. But `warn`, `ok` and `die` all print to **stdout**, so on the from-source branch the substitution captured:

```
⚠ first run: compiling the control plane (one-time; later runs skip this)
/tmp/fbx-rc-fresh/target/debug/fluidbox-server
```

and the launcher exec'd that whole multi-line string as a command name. The cargo build **succeeded** (a 120 MB binary, timestamped); the demo still died at the health timeout with a misleading `No such file or directory` and exit 2. `die` inside the substitution was invisible for the same reason, and its `exit 1` only left the subshell.

**Why every prior drill missed it:** `docs/reviews/2026-07-29-demo-validation/README.md` records that all eight drills set `FLUIDBOX_DEMO_SERVER_BIN` to a prebuilt binary — which takes an early return that prints nothing.

Fixed with a `SERVER_BIN` global (a variable has no stream to pollute). `scripts/demo-selftest.sh` pins it and **generalises** it: it flags any `X=$(fn)` where `fn` is defined in the script and its body calls a printer, so the next instance is caught rather than only this one. 9 assertions, red-green verified on all four defects it covers, running in CI.

### 4.3 An unshared checkout produced a meaningless success

The `/tmp` fresh-clone run *completed* — 5 gate decisions, exit 0, teardown clean — and every command inside it had failed with `No such file or directory`, the diff artifact was 0 bytes, and the receipt said "(no changes)" and "4 executed, 1 denied".

Cause, measured directly:

```
/tmp                    -> <EMPTY>        (bind mount produced an empty directory)
/Users/hrishikeshkakkad -> marker.txt ✓
```

colima shares only the paths it was started with; Docker Desktop has an explicit File Sharing list. A checkout outside either is invisible to the daemon, and docker **mounts an empty directory rather than failing**. The demo now writes a marker into the data dir and reads it back from inside a container before the control plane starts, refusing with the cause and the fix for both engines:

```
✗ the docker daemon cannot read files from this checkout.
    • colima      — started with --mount; $HOME is shared, /tmp usually is not.
    • Docker Desktop (macOS/Windows) — add this directory under File Sharing
  This checkout: /tmp/fbx-mountfail
```

This is the third instance of one pattern in this codebase: **an environment problem wearing the costume of a result.** The others were the exit-0 receipt and the daemon mismatch.

### 4.4 The tool vocabulary, and a latent bypass

23 advertised tools had no rule. All are now registered in `CANONICAL` (required — `seed_policy_matches_are_all_known_tools` enforces it) and grouped by what they do: observational → **allow**; effects outliving the run → **approve** with a `risk` string; `DesignSync` → **deny** with the other egress tools; and **sub-execution → deny**.

The deny is the security decision. `Agent`, `Task`, `Workflow`, `Skill`, `TaskCreate` start execution whose nested calls may never surface as top-level blocks, so they would be neither routed by the hook nor caught by the tripwire — which documents itself as "a knowingly incomplete detector" for exactly this. `approve` would mean one human click authorising an unbounded, unobserved tool tree.

**The latent bypass neither review caught:** the previous seed **allowed `Task`**, inert only because this CLI names its subagent tool `Agent`. A standing allow-rule for a sub-execution tool, waiting for an upstream rename. It is now in the deny rule.

`seed_policy_governs_the_advertised_surface` pins both halves and asserts an unregistered tool still falls to the fail-safe default, so no catch-all was introduced.

## 5. Zero-state validation

Platform: **macOS 15.6 arm64 host, colima Linux arm64 VM, Docker 29.5.2.** Stated plainly because it bounds every result below.

### 5.1 Fresh clone, clean image state, documented first-run path

Cloned the committed RC into an empty directory (no `.env`, no `target/`), removed the replay image under a distinct tag so the cold build was measured **without touching the maintainer's images**, and ran the documented command.

| Measurement | Value |
|---|---|
| Commands required from clone to completed demo | **2** (`git clone`, `just demo`) |
| Repository clone | 2s, 413 files |
| Cold control-plane compile (first run only) | **58s** (warm cargo registry; a truly cold registry is longer) |
| Replay runner image build | ~3s (dependency-free by design) |
| Replay runner image size | **485 MB** |
| Sandbox runner image size (for live runs) | 1.67 GB |
| Demo wall time **once built** | **12s** |
| Gate decisions | **5** — 3 policy-allow, 1 policy-deny naming `\bcurl\b`, 1 human-allow after the approval pause |
| Model spend | **$0.00**, 0 model requests |
| Diff produced | real: `app.js` repaired *and* `deploy.log` created |
| Teardown | complete (below) |

The run is genuinely governed end-to-end: `./run_tests.sh` really failed (`FAIL greet("Ada") -> "Hello, name!"`), `app.js` was really edited, the re-run really passed, `curl` was denied by policy naming the matched pattern, and `./deploy.sh` waited for a human.

**Time to first demo for a new user is the 58s compile plus 12s ≈ 70 seconds**, well inside the beta's 10-minute median threshold — but that assumes a Rust toolchain already installed and a warm cargo registry. Neither is true of every participant, which is why the participant guide warns about it explicitly.

### 5.2 Teardown completeness, measured against live contention

The maintainer's dev stack was left running throughout, so isolation was tested against real contention rather than an empty machine.

```
demo containers 0 · demo volumes 0 · replay containers 0 · per-run networks 0
.demo/ removed · ports 19790/19791/15434 all free
maintainer dev stack: 2/2 still running · deploy_fluidbox-pgdata volume intact
```

### 5.3 Failure matrix

| Scenario | Result |
|---|---|
| Deterministic replay without API keys | **PASS** — no key needed, stated up front |
| Repeated invocation | **PASS** — refused, naming the pid and `just demo-down` |
| Port collision | **PASS** — names the port, the `lsof` line, and `FLUIDBOX_DEMO_PORT` |
| Missing Docker | **PASS** — refuses with start instructions, creates no state |
| Control-plane never healthy | **PASS** — bounded 60s wait, last log lines, log path, automatic teardown, exit 2 |
| Malformed configuration | **PASS** — strict parser refuses the boot: `unknown field 'bogus_unknown_key', expected one of …` plus *why* it refuses (the policy does not exist yet, so the file is its only source) |
| Docker cannot share the checkout | **PASS (new)** — refuses with the cause and the per-engine fix |
| Interrupted startup / restart / reinstall | **PASS** — teardown reaps the control plane, containers, volume and `.demo/`; a subsequent run succeeds |
| Denial with no side effect | **PASS** — gate proof B, and the demo's `curl` deny |
| Approval before execution | **PASS** — gate proof E, measured 37ms after a 6.01s held verdict |

### 5.4 Upgrade, migration, rollback

`v0.3.0` ships 25 migrations; this candidate adds `0026_policy_versions.sql`, which drops four columns. Because `sqlx::migrate!` bakes files at compile time, a "v0.3.0-shaped" binary was produced by building with only the first 25 present.

| Direction | Result |
|---|---|
| **Upgrade:** candidate binary against a 25-migration database | **PASS** — applied `0026`, booted healthy, `max(version)` → 26 |
| **Rollback:** pre-`0026` binary against a 26-migration database | **PASS — refuses loudly**: `migration 26 was previously applied but is missing in the resolved migrations` |

So the CHANGELOG's "no binary rollback past `0026`, and it fails loudly rather than silently" is now **verified rather than asserted**.

**One harness artifact, reported rather than hidden:** booting the v0.3.0-*shaped* binary against an empty database applied all 25 migrations and then failed seeding with `null value in column "yaml_source"`. That is not a v0.3.0 defect — it is *current* seeding code (which no longer writes `yaml_source`, since `0026` drops it) compiled against a pre-`0026` schema. A genuine v0.3.0 binary would have written the column. The migrations themselves applied cleanly, which is all the upgrade test needed.

### 5.5 Live model runs

| Harness | Outcome | Cost |
|---|---|---|
| **Claude** | **NOT POSSIBLE.** `HTTP 400 — Your credit balance is too low to access the Anthropic API`, confirmed directly (`req_011CdXg5svpfccuToeZzPtyD`) and through the LiteLLM gateway | $0.00 |
| **Codex** | **PASS, twice** | **$0.0031** |

The Codex runs answer a question the integration review left open ("Codex harness unexamined"). With a policy denying `Bash`, autonomous mode, and an unfabricatable nonce:

```
tool.requested  Bash: printf fbxcodex-… | sha256sum
tool.decision   deny (source=policy) denied for the codex gate probe
digest of the fresh nonce present in the ledger? no
run.result: completed — The command was not executed because the environment rejected it.
```

Repeated with `cd /usr/bin && printf … | ./sha256sum` — the **relative-path spelling disclosed in issue #15** as escaping the execpolicy's prefix matching. It **also reached the gate** and was denied. So the disclosed escape does not bypass fluidbox's gate in this configuration. That is one probe of one class, not a proof that the enumeration is complete.

**Total live-model spend for this pass: $0.0031 against a $10 cap.** The cap was never the constraint; available credit was.

## 6. Complete check re-run, after every change

```
fmt                    rc=0
clippy                 rc=0   (-D warnings)
test                   rc=0   857 passed, 0 failed
version-check          rc=0   15 sites agree at 0.4.0-rc.1
compose-check          rc=0   14 passed, 0 failed
demo-selftest          rc=0   9 passed, 0 failed
node-runner-lib        rc=0   21 passed, 0 failed
node-replay            rc=0   8 passed, 0 failed
helm-lint              rc=0
web-build              rc=0
gate-proof             rc=0   14 passed, 0 failed
```

857 rather than 856: `seed_policy_governs_the_advertised_surface` is new. `fmt` failed once on that test and was corrected.

**Not run, with reasons.** The full `just e2e` — its live-agent phases need credits the key does not have, and issue #100 records four pre-existing red phases, so its result would not be attributable to this candidate; the two suites that actually cover the changed governance path (`e2e-tool-gate`, `governance-e2e`) were run by the integration review and reproduced there. **EKS acceptance** — the mandate forbids creating cloud resources.

## 7. Remaining risks

Ordered by what I would want a maintainer to weigh first.

1. **No live Claude run.** The security property is proven without a model, and more rigorously than a live run would. But "a real model completes a real task on the Claude harness" is unproven for this candidate. **This is the single strongest argument against `RC READY TO PUBLISH`.** Cost to close: one funded key and about ten minutes.
2. **One platform, one architecture.** macOS arm64 host, Linux arm64 containers. amd64 untested; a Linux *host* untested; Windows untested. CI covers Linux/amd64 and will execute the new jobs on the next pipeline run, which had not happened.
3. **Supply chain unchanged (BLK-07).** No lockfile for either runner image, `npm install` not `npm ci`, no npm Dependabot entry for the runner directories, no signing, no SBOM, no attested provenance, no checksums, and every third-party Action floating on a mutable tag in a job holding `packages: write`. For a product whose promise is containment and accountability, the code that runs *beside the workspace* is the least verifiable thing it ships. Now stated bluntly in the compatibility matrix rather than left to inference.
4. **Nested sub-execution routing is untested.** Mitigated by denying it in the seed, which is a policy control, not a mediation proof.
5. **An old pinned `runner_image` on a new server routes nothing**, and AT-01a — server-side detection of a terminal run with a non-empty diff and zero `tool.decision` events — is still not built. It needs no harness cooperation and remains the highest-value detection work outstanding.
6. **Kubernetes not re-validated for this candidate.** The admission fix has strong recent evidence (12/12 kind, 9/9 EKS) but the two full EKS acceptances predate it.
7. **One unexplained demo hang.** During the first `$HOME` fresh-clone run the session stuck at `awaiting_approval` after the approval was granted and `tool.decision: allow` was written; the sandbox container had vanished from `docker ps -a` with nothing in the server log. It **did not reproduce** on a clean re-run (exit 0, 12s, real diff). The environment had three `fluidbox-server` processes and several parallel agents on one Docker daemon, which is a documented footgun (the boot orphan sweep reaps containers whose session is absent from *its* database). I could not attribute it, so I am neither calling it a defect nor pretending it did not happen. A beta with twenty participants is a reasonable instrument for finding out whether it recurs.
8. **Release publishing is ungated** by deliberate choice. The Release PR's own CI is the last checkpoint before permanent public artifacts.

## 8. Artifact inventory

### New

| Path | What it is |
|---|---|
| `scripts/gate-proof.sh` + `scripts/gate-proof/mock.py` | the keyless permission-gate proof, 14 assertions, in CI |
| `scripts/demo-selftest.sh` | static self-checks for the demo, 9 assertions, in CI |
| `deploy/compose-assertions.sh` | compose-file guard, 14 assertions, in CI |
| `docs/release/claims-matrix.md` | every material claim → evidence class → verifying command |
| `docs/release/compatibility-matrix.md` | validated vs expected, per platform/engine/provider, plus the artifact-verifiability table |
| `docs/release/upgrade-and-rollback.md` | the 0.3.0 → 0.4.0-rc.1 path, with the verified rollback refusal |
| `docs/beta/` (10 files, 1,383 lines) | the private-beta package |
| `docs/reviews/release-candidate-readiness.md` | this document |

### Changed

`policies/default.yaml` and `crates/fluidbox-core/src/tools.rs` (23 tools + the nesting deny) · `crates/fluidbox-core/src/policy.rs` (the pinning test) · `deploy/docker-compose.eval.yml` · `scripts/demo.sh` · `scripts/version-check.sh` · `images/runner-lib/gate.test.mjs` · `.github/workflows/ci.yml` (three new gates) · `justfile` · `README.md`, `SECURITY.md`, `CLAUDE.md`, `PLAN.md`, `docs/ARCHITECTURE.md`, `docs/hosted/threat-model.md` · `CHANGELOG.md` and all 15 version sites.

### Not touched, deliberately

`main`; the four source worktrees; the sibling film repository (`~/Documents/fluidbox-demo-film`) — **its clips remain NOT cleared for publication**: four assert "EVERY TOOL CALL", which is still unsupportable (Codex measured for one class, an old image routes nothing), and `docs/clips/CLAIMS.md` still says the gate fix shipped when it had not. The honest replacement wording is in the claims matrix.

## 9. Proposed release

| | |
|---|---|
| **Version** | `0.4.0-rc.1` |
| **Commit** | tip of `release/prime-time-rc` (see §11) |
| **Tag** | `v0.4.0-rc.1` — **not created** |
| **How to publish** | dispatch `release.yml` with `version: 0.4.0-rc.1`. Its chart job already accepts a SemVer prerelease; `version-check.sh` now does too |

Minor rather than patch: pre-1.0 with `bump-minor-pre-major`, and the candidate carries changes an operator must act on.

**One change a maintainer should confirm before publishing.** The bump also moves `.release-please-manifest.json` to `0.4.0-rc.1`. That file is release-please's memory of the last release, and `version-check.sh` asserts it equals canonical, so the two cannot disagree. If you would rather release-please keep believing `0.3.0` was the last release, revert that one line and publish by dispatch.

### Release-note draft

> **fluidbox v0.4.0-rc.1** — a release candidate whose headline is a security fix, and whose second headline is that the fix is now provable without spending a cent on a model.
>
> **The permission gate is enforced for every tool call on the Claude harness.** It was not. `canUseTool` is not an interception point: the SDK translates it into the CLI's `--permission-prompt-tool`, which the CLI consults only for calls it decides to *ask* about — so its read-only and safe-command classifications executed with the callback never running and zero decisions in the ledger. Closed with a mandatory, unscoped `PreToolUse` hook plus a tripwire that fails the run if a result arrives for a call nothing decided.
>
> **`scripts/gate-proof.sh` proves it on every pull request, with no API key.** The real runner image and the real pinned CLI against a mock upstream and a mock control plane, asserting on real filesystem side effects and on the digest of a freshly-minted nonce. 14 assertions including allow-path positive controls, a held-verdict ordering proof, and five fail-closed variants.
>
> **The eval quickstart no longer ships a working admin credential.** The token is required; the dashboard is loopback-only; the API port's necessary exposure is documented rather than implied away, and guarded in CI.
>
> **Kubernetes: the NetworkPolicy enforcement race is closed at both layers** — a bounded observation protocol plus a per-sandbox admission gate that holds the untrusted runner until the pod's own network is observed enforced. 12/12 kind + Calico, 9/9 real EKS.
>
> **Also:** `just demo` — a five-minute first run with no API key — now fails when the run fails, refuses when the daemon cannot read your checkout, and works from a fresh clone. The seed policy governs 23 previously-ungoverned tools and **denies sub-execution**.
>
> **Read before upgrading:** the seed policy does **not** re-apply to an existing deployment; import `policies/default.yaml` or every supervised run will pause on ordinary agent tooling. See [`docs/release/upgrade-and-rollback.md`](docs/release/upgrade-and-rollback.md).
>
> **Known limitations, stated up front:** no live Claude run was validated (the available key is out of credit); one platform and architecture were validated (macOS arm64 host, Linux arm64 containers); release artifacts remain unsigned with no SBOM, provenance, or checksums, and the runner images are not reproducible. Full detail in [`docs/release/claims-matrix.md`](docs/release/claims-matrix.md) and [`docs/release/compatibility-matrix.md`](docs/release/compatibility-matrix.md).

## 10. Beta launch checklist

Before inviting anyone:

- [ ] Read [`docs/beta/private-beta-plan.md`](../beta/private-beta-plan.md) and confirm the four personas and the eight thresholds are what you want to be held to.
- [ ] **Fund an Anthropic key** and do one live Claude run. It is the largest gap and the cheapest to close.
- [ ] Run `just demo` on a machine you have not used before, ideally Linux/amd64, and time it honestly.
- [ ] Decide the `.release-please-manifest.json` question (§9).
- [ ] Publish the RC (`release.yml` dispatch, `version: 0.4.0-rc.1`) so participants install a tagged artifact rather than a branch.
- [ ] Confirm the private vulnerability-reporting path works end to end by filing a test advisory.
- [ ] Do **not** publish the film clips (§8).
- [ ] Set up the participant tracking sheet from [`metrics-scorecard.md`](../beta/metrics-scorecard.md) with 20 blank rows.
- [ ] Send [`invitation-draft.md`](../beta/invitation-draft.md), adapted, to 20 people across the four personas.

During:

- [ ] Run the [`daily-triage.md`](../beta/daily-triage.md) loop each morning.
- [ ] Escalate any failure mode reaching a **third** participant — that breaches a stated threshold.
- [ ] Route any suspected vulnerability to private disclosure, never a group channel.
- [ ] Halt the beta on a new P0.

## 11. Commits on this branch

Eight commits on top of the integration:

```
fix(eval):     require an admin token; loopback the dashboard; guard both in CI
fix(core):     govern every tool the pinned CLI advertises; deny sub-execution
fix(demo):     fail when the run fails; agree with the server on the docker daemon
feat(ci):      prove the permission gate with no model spend, and gate it on every PR
fix(release):  let the version guard express a prerelease
docs:          correct the gate, egress and acceptance claims to what is actually proven
chore(release): 0.4.0-rc.1
fix(eval):     quote the required-token message, and make the guard parse the file
fix(demo):     the from-source first run was broken; add static self-checks
fix(demo):     prove the daemon can read the checkout before running
docs(release):  claims matrix, compatibility matrix, upgrade/rollback guide, beta package
```

## 12. Reproduction

```bash
# the permission gate — no API key, no model spend
just gate-proof

# the five-minute first run — no API key
just demo

# the guards that did not exist before this candidate
bash deploy/compose-assertions.sh
bash scripts/demo-selftest.sh
bash scripts/version-check.sh

# the full bar (use a throwaway DATABASE_URL, never the dev database)
cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings \
  && cargo test --workspace && (cd apps/web && pnpm build)
node --test images/runner-lib/*.test.mjs
node --test images/replay-runner/runner/test/*.test.mjs
helm lint deploy/helm/fluidbox
```
