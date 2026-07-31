# Claims matrix — `v0.4.0-rc.1`

Every material public claim fluidbox makes, what class of evidence supports it,
and the command you can run to check. This exists because a previous release
shipped four sentences that a security-conscious adopter would rely on and that
were measurably false; the remedy is not better prose, it is a maintained list
with a reproduction next to each row.

**Classes.** **PROVEN** — an executable artifact asserts it, and that artifact
runs somewhere that gates a change (CI on pull requests, or a recorded
acceptance). **PROVEN, NOT GATED** — the artifact exists and passes, but nothing
requires it to. **PARTIAL** — true of part of its stated scope; the narrowing is
named. **INFERRED** — correct by reading the code, with no executable assertion.
**NOT CLAIMED** — listed because a reader might assume it; we do not assert it.

> **The one qualification that colours several rows.** For **brokered MCP** tools
> the control plane *executes* the call, so the gate is structural. For
> **in-sandbox** tools (`Bash`, `Edit`, `Read`, sandbox stdio MCP) the sandbox
> executes them and the gate binds because the runner **routes** every call to
> it. Routing is a real control against a prompt-injected model. It is not a
> control against a workload already executing arbitrary code, and an older
> pinned `runner_image` routes nothing. Rows that inherit this say so.

---

## Enforcement and governance

| # | Claim | Class | Evidence |
|---|---|---|---|
| A1 | Brokered MCP calls cannot execute without a server-side decision. | **PROVEN** | Structural — `broker.rs` executes the call. `scripts/hardening-e2e.sh` (CI, every PR). |
| A2 | On the Claude harness, every tool call is routed to that decision by a mandatory `PreToolUse` hook, and a denial prevents execution. | **PROVEN** | `scripts/gate-proof.sh` — 14 assertions, CI on every PR, **no API key**, green on **two architectures** (macOS/arm64 local, Linux/amd64 in CI). Denied read-only probe: gate consulted, nonce digest absent from all traffic. Denied mutating probe: no file. Allow-path positive controls both fire. Held-verdict ordering proof: verdict held 6.01s, side effect appeared 37ms *after* it. |
| A3 | The gate fails closed on a broken control plane. | **PROVEN** | `gate-proof.sh` §F: HTTP 500 → retries indefinitely (5 attempts in 25s), never executes; `401` → hard deny; `403 wrong_audience` → runner **aborts** (exit 3) rather than converting a credential fault into a verdict; non-JSON and `{}` → deny. |
| A4 | On the Codex harness, a policy denial prevents execution. | **PROVEN (live, twice)** | Two live runs, `gpt-5.4-mini`, $0.0031 total: `tool.requested` → `tool.decision: deny (source=policy)`, the digest of a freshly-minted nonce **absent** from the ledger. Repeated with the relative-path spelling disclosed in issue #15, which also reached the gate. Recorded, not CI-gated. |
| A5 | Nested sub-execution is gated. | **NOT CLAIMED** | `Agent`, `Task`, `Workflow`, `Skill`, `TaskCreate` may not surface nested calls as top-level blocks, so they could be neither routed nor caught by the tripwire. **The seed policy denies all five**, pinned by `seed_policy_governs_the_advertised_surface`. The routing question itself is untested — the honest status is that we refuse rather than that we mediate. |
| A6 | An old pinned `runner_image` on a new server is gated. | **NOT CLAIMED — and not detected.** | Mediation is runner-side by construction. There is still no server-side check for a terminal run with a non-empty diff and zero `tool.decision` events. Containment is the binding control. |
| A7 | Autonomy changes *who answers*, never *whether it is asked*. | **PROVEN in the evaluator; inherits A2/A6 end to end** | `policy.rs` rewrites `RequireApproval` to the fallback inside `evaluate()`, recording both verdicts; `AutonomousFallback::default() == Deny`. `governance-e2e.sh`. |
| A8 | Approvals are idempotent by `(session_id, tool_call_id)`. | **PROVEN** | `governance-e2e.sh` (47/47 reproduced) and `hardening-e2e.sh`. A replay with different input hard-denies without touching the stored verdict. |
| A9 | Authority is frozen before spend; later edits affect future runs only. | **PROVEN** | Frozen `run_spec` measured byte-identical across migration `0026`, which drops four columns. `governance-e2e.sh` asserts byte-equality. |
| A10 | Attach does not mean allow. | **PROVEN for the frozen-set/schema/drift checks; inherits A2 for in-sandbox tools** | `hardening-e2e.sh` (CI). |
| A11 | Fork PRs lose their MCP surface and get a read-only floor approvals cannot widen. | **PARTIAL — the two halves differ in strength** | MCP stripping is **structural**, before provisioning (`bindings.rs`, unit-tested) and needs no gate. The `Bash`/`Edit`/`Write` floor is enforced *at the gate*, so against an anonymous fork-PR author it is only as strong as A2 plus containment. |
| A12 | The ledger accepts only redacted events; prompts never reach it. | **PROVEN** | Type-level (`Redacted<EventEnvelope>` constructible only via `Redactor::scrub`); `secrets-e2e.sh` greps every per-boot log (CI). |
| A13 | The seed policy states an opinion about every tool the pinned CLI advertises. | **PROVEN** | `seed_policy_governs_the_advertised_surface` asserts every `CANONICAL` name resolves to a rule rather than the fallback, and that no nesting tool is ever `allow`. |

## Credentials and isolation

| # | Claim | Class | Evidence |
|---|---|---|---|
| B1 | No real upstream credential is placed in a sandbox. | **PROVEN** | Four independent paths keep the secret control-plane-side. `secrets-e2e.sh` + the k8s `token-never-leaks` manifest test (CI). The strongest property in the product. |
| B2 | The sandbox holds four audience-scoped tokens, not one bearer. | **PROVEN** | An exhaustive route × audience matrix in `hardening-e2e.sh` asserts the body is byte-equal to `{"error":"wrong_audience"}` (CI). Independently observed in the gate proof: `wrong_audience` makes the runner exit 3. |
| B3 | The runner-control credential is not in `/proc/<pid>/environ`. | **PROVEN on Linux** | The entrypoint hands it over on an unlinked fd and `exec`s. `images/runner-lib/entrypoint.test.mjs` — three assertions are Linux-only and self-skip on macOS, so **CI is where they actually execute**. |
| B4 | Same-uid `ptrace` can still read the token from live memory. | **DISCLOSED RESIDUAL** | Not mitigated. `cap_drop: ALL`, `no-new-privileges` and seccomp `RuntimeDefault` do not block same-uid ptrace. |
| B5 | Tenant isolation is a signature requirement with a database floor. | **PROVEN** | `TenantScope` in every tenant-owned repository signature; 37 tables `ENABLE`+`FORCE` RLS; the negative matrix runs as the non-owner `fluidbox_runtime` role in three CI jobs. |
| B6 | The sandbox has no network egress. | **FALSE on the Docker default — do not claim it** | `NetworkMode::HostDev` is the `#[default]`: general internet egress **plus** `host.docker.internal`, i.e. the host's network position. Closed by Kubernetes `zeroEgress` and Docker `Hardened`. `docs/ARCHITECTURE.md` and `CLAUDE.md` previously said "egress-free" and were corrected in this release. |
| B7 | Kubernetes blocks run admission until NetworkPolicy enforcement is proven, per sandbox as well as at boot. | **PROVEN, recorded acceptance** | Bounded observation protocol + `netpol-gate` init container placed first in every sandbox pod. 12/12 kind + Calico, 9/9 real EKS 1.33, including reproducing the pre-fix vulnerability natively. Not re-run for this candidate; no cloud resources were created. |

## Deployment and operations

| # | Claim | Class | Evidence |
|---|---|---|---|
| C1 | The eval Docker profile is for trying the run loop, not for exposing to a network. | **NOW TRUE, WITH A NAMED RESIDUAL** | The published admin-token default is gone (compose refuses without one, guarded per service and on the rendered document) and the dashboard is loopback. The **API port is still published on all interfaces by default**, so the token is the control, not your network position. `deploy/compose-assertions.sh` (CI) guards all of it. **Correction, 2026-07-30:** this row previously said the API port "cannot be loopback-bound". That was false — see C1a. |
| C1a | Whether the eval API port can be narrowed to loopback. | **ENGINE-DEPENDENT — measured on one engine only** | `FLUIDBOX_EVAL_API_BIND=127.0.0.1` was **measured reachable on colima**: a `127.0.0.1`-published port answered on `host.docker.internal` from a sibling container, including one on its own isolated per-run network. Docker Desktop/OrbStack share that port-forwarding shape and are **EXPECTED** to behave the same (unmeasured). On **native Linux Docker**, `host-gateway` is the bridge gateway and a loopback publish is **EXPECTED to break** (unmeasured). No end-to-end fluidbox run was completed with the loopback bind — only the network path was measured. The default stays open for portability, not because narrowing is impossible. Reproduction in [`../reviews/rc-verification-2026-07-30.md`](../reviews/rc-verification-2026-07-30.md) §3. |
| C2 | An operator may name any control-plane host path as a `local_copy` workspace. | **TRUE, AND INTENDED** | Operator-only and non-empty are the only checks; there is no root or canonicalisation. Combined with C1 this is why the eval profile needs a trusted network. |
| C3 | `just demo` is a five-minute first run needing no API key. | **PROVEN** | Fresh clone, from-source build: 5 gate decisions (3 policy-allow, 1 policy-deny naming `\bcurl\b`, 1 human-allow), a real diff (`app.js` repaired **and** `deploy.log` created), `$0.00`, 0 model requests, 12s once built, complete teardown with the maintainer's dev stack untouched. |
| C4 | Upgrading from `v0.3.0` applies migration `0026` on boot. | **PROVEN** | The candidate binary against a 25-migration database applied `0026` and booted healthy. |
| C5 | There is no binary rollback past `0026`, and it fails loudly. | **PROVEN** | A pre-`0026` binary against a `0026` database refuses with `migration 26 was previously applied but is missing in the resolved migrations`. |
| C6 | `just check` runs fmt, Clippy `-D warnings`, tests, and the web build. | **PROVEN** | Reproduced independently: **856 tests, 0 failed**, fmt clean, Clippy clean, dashboard build exit 0. |
| C7 | The acceptance suites cover the control plane, dashboard, both harnesses, connectors, identity and isolation. | **PARTIAL — "cover" ≠ "gate"** | Gated on every PR: Rust, dashboard, identity/bindings/secrets/hardening/scale, `cargo-deny`, version + compose guards, both node suites, and the gate proof. **Not** gated: the full `just e2e` live-agent tiers (`workflow_dispatch` only, four phases known red, issue #100). Publishing is ungated by choice. |
| C8 | `just doctor` checks the documented failure points. | **INFERRED** | `scripts/doctor.sh` covers the gotchas; nothing asserts doctor's own correctness and it does not run in CI. |

## Supply chain

| # | Claim | Class |
|---|---|---|
| D1 | Release images are signed / an SBOM is published / provenance is attested / the chart is signed / checksums are published. | **NOT CLAIMED — and none of these exist.** See the compatibility matrix for the full table. |
| D2 | Runner images are reproducible. | **PARTIAL — the dependency graph is now pinned; the image still is not.** Both runners carry a `package-lock.json` and build with `npm ci` (2026-07-31), so two builds of one commit resolve the SAME dependency tree and a lock/manifest disagreement FAILS the build. That is not full reproducibility: the base image tag, apt/apk layers and build timestamps are still unpinned, so image digests can differ. Verified: the sandbox runner rebuilt under `npm ci` and passed `gate-proof.sh` 14/14. |
| D3 | Runner dependencies are monitored for CVEs. | **NOW TRUE (2026-07-31).** Both runner directories have an npm Dependabot entry, grouped minor/patch weekly. Agent-SDK and MCP-SDK **majors are deliberately excluded** — a major can change the harness contract the permission gate depends on, so it is taken by hand with `gate-proof.sh` adjudicating. Watching them at all was only possible once each directory had a lockfile. |
| D4 | This candidate does not claim a proven 300-run production ceiling. | **CORRECTLY SCOPED** | The 60/150/300-concurrent-run campaign has not been executed. Capacity remains a deployment gate. |

## Maturity

| # | Claim | Class |
|---|---|---|
| E1 | fluidbox is pre-1.0 security software whose guarantees come from explicit boundaries. | **TRUE, with A2's qualification stated in the same breath.** For in-sandbox tools one of those boundaries depends on the agent *runtime* cooperating — not on the agent reasoning well, but on the harness routing. The README now says this in the first security bullet rather than in a footnote. |
| E2 | A live model completes a real task on the Claude harness in this candidate. | **NOT VALIDATED** | The available Anthropic key is out of credit (HTTP 400, confirmed twice). The gate proof is a stronger witness for the *security* property and no substitute for this *usability* one. |

---

## Reproducing this matrix

Every **PROVEN** row above is reachable from a clean checkout with the commands
listed in [`compatibility-matrix.md`](compatibility-matrix.md#how-to-reproduce-any-row-marked-validated).
The full run log, with timings and outputs, is
[`../reviews/release-candidate-readiness.md`](../reviews/release-candidate-readiness.md).

The predecessor of this file is
[`../reviews/public-claims-audit.md`](../reviews/public-claims-audit.md) — the
independent audit that found the contradicted claims. It is kept as written,
including its verdicts, because a corrected audit is less useful than an audit
plus a record of what changed.
