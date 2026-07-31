# Compatibility matrix — `v0.4.0-rc.1`

**What this document is for:** to let you find out whether fluidbox has been *run*
on your shape of machine, as opposed to whether it is *expected* to work there.
Those are different claims and this file keeps them apart.

The rule used throughout: **VALIDATED** means someone ran it on that combination
and recorded the result for this candidate. **EXPECTED** means the code has no
known reason to fail there and nobody has checked. **NOT VALIDATED** means
exactly that — not "broken", and not "fine".

Nothing in the EXPECTED column should be read as a support commitment.

---

## Host platform and architecture

| Host | Arch | Status for this candidate | Notes |
|---|---|---|---|
| macOS | arm64 (Apple silicon) | **VALIDATED** | The whole validation for this candidate ran here: fresh-clone `just demo`, the gate proof, a live Codex run, the failure matrix, and the migration/rollback test. Docker engine was colima (Linux arm64 VM). |
| macOS | amd64 (Intel) | **NOT VALIDATED** | No Intel Mac was available. |
| Linux | arm64 | **NOT VALIDATED as a HOST** | Linux arm64 *containers* were exercised throughout (every sandbox, the runner images, Postgres), but the control plane itself was not run on a Linux host for this candidate. |
| Linux | amd64 | **VALIDATED for CI-executed paths** (updated 2026-07-31) | The pipeline on PR #105 ran green on `ubuntu-latest`: Rust suite, dashboard build, `deny`, `chart`, `version-check`, `compose-check`, `secrets`, `identity`, `bindings`, `hardening`, `scale`, `kind-calico`, and **`gate-proof` 14/14** — the permission gate proven on a second architecture. **Not** covered here: `just demo` (no CI job) and any live-model run. The first run on this platform also *found* a real defect the macOS validation had hidden — a `0600` side-effect file that colima's uid remapping made readable and native Linux did not; see [`../reviews/rc-verification-2026-07-30.md`](../reviews/rc-verification-2026-07-30.md) §12. |
| Windows | any | **NOT VALIDATED** | No Windows environment was available. WSL2 is the only plausible path and it was not tried. |

**Do not read the macOS row as "macOS is the supported platform."** It is the
platform this candidate happens to have been validated on, because that is the
machine the work was done on.

## Container engine

| Engine | Status | Notes |
|---|---|---|
| colima | **VALIDATED** | Used for every container operation in this validation. |
| Docker Desktop | **EXPECTED** | The demo now resolves the daemon endpoint from the active `docker context` and exports it, which is the mechanism Docker Desktop needs. Not exercised for this candidate — the VM on the validation machine had been deleted. |
| OrbStack | **EXPECTED** | Same mechanism as Docker Desktop. Not exercised. |
| Podman | **NOT VALIDATED** | The provider uses bollard against a Docker-API socket; Podman's compatibility socket may work and has not been tried. |

**Engine-specific trap that bites on every engine.** fluidbox bind-mounts the
run's workspace from the host into the sandbox, and an engine that cannot share
that host path mounts an **empty directory** rather than failing. The run then
completes with every command reporting "No such file or directory", a 0-byte
diff, and a success-shaped receipt. `just demo` now probes for this before
starting and refuses with the fix. Keep your checkout somewhere the engine
shares — under `$HOME` is the reliable answer for colima, and inside Docker
Desktop's File Sharing list on macOS/Windows.

## Execution providers

| Provider | Status | Notes |
|---|---|---|
| Docker | **VALIDATED** | The demo, the gate proof, and the live Codex run all used it. |
| Kubernetes | **NOT RE-VALIDATED for this candidate** | The NetworkPolicy admission protocol in this release was validated 12/12 on kind + Calico and 9/9 on real EKS 1.33 on 2026-07-29 (`docs/reviews/k8s-network-admission-validation.md`). The two full EKS acceptances (2026-07-17, 2026-07-22) **predate** the admission defect this release fixes and have not been re-run. No cloud resources were created for this candidate. |
| AWS Lambda MicroVM | **NOT BUILT** | Planned; `SandboxHandle` is already serializable for reattach. |

## Harnesses

| Harness | Status | Notes |
|---|---|---|
| Codex (`gpt-5.4-mini`) | **VALIDATED LIVE** | Two live runs. A policy `deny` on `Bash` was reached and enforced: `tool.requested` → `tool.decision: deny (source=policy)`, the digest of a freshly-minted nonce appeared **nowhere** in the ledger, and the agent reported the command was rejected. Repeated with a relative-path spelling (`cd /usr/bin && … | ./sha256sum`) — the escape disclosed in issue #15 — which **also** reached the gate. Total cost $0.0031. |
| Claude Agent SDK | **VALIDATED WITHOUT A MODEL** | The permission gate is proven end-to-end by `scripts/gate-proof.sh` — real runner image, real pinned CLI, real side effects, 14 assertions, no API key. **No live Claude run was performed for this candidate**, because the available Anthropic key is out of credit (HTTP 400, confirmed against the API directly and through the gateway). So "a real model completes a real task on this harness" is *not* validated here, even though the security property is. |
| Deterministic replay (`just demo`) | **VALIDATED** | Fresh clone, 5 gate decisions, real diff, $0.00. |

## Databases

| Database | Status | Notes |
|---|---|---|
| PostgreSQL 17 (container) | **VALIDATED** | Local dev and every test in this validation. |
| PostgreSQL 16 | **EXPECTED** | What CI uses. |
| Neon (hosted) | **NOT VALIDATED for this candidate** | Nothing in the Rust is Neon-specific. Use the **direct** (non-`-pooler`) connection string: PgBouncer transaction mode breaks sqlx prepared statements and `LISTEN/NOTIFY`. |

## Toolchain prerequisites

| Tool | Needed for | Notes |
|---|---|---|
| docker | everything | The demo needs the daemon to be able to share your checkout — see above. |
| git | workspace materialisation | |
| python3 | `just demo`, the gate proof, several suites | Standard library only; no pip installs. |
| Rust toolchain | building the control plane | Only for the from-source path. The first `just demo` in a fresh clone compiles it — about a minute on the validation machine with a warm cargo registry, longer cold. This is not a hang. |
| pnpm + Node | the dashboard | Not needed for `just demo`. |
| psql ≥ 15 | some acceptance suites | A 14.x client silently returns only the last result of a multi-statement `-c`, which shows up as empty captures. |

## Release artifacts — what a consumer can and cannot verify

| Property | Status |
|---|---|
| Multi-arch images (amd64 + arm64) published to GHCR | yes, built natively per arch |
| OCI Helm chart published to GHCR | yes |
| Prerelease versions publishable | yes — `release.yml`'s chart job accepts a SemVer prerelease, and `scripts/version-check.sh` now does too |
| Images **signed** (cosign/sigstore) | **NO** |
| **SBOM** published | **NO** |
| Build **provenance** attested | **NO** — and the multi-arch index is assembled with `docker buildx imagetools create` from bare digests, which would not carry per-arch attestations forward even if they existed |
| Helm chart signed | **NO** (`helm package` without `--sign`) |
| **Checksums** published for release artifacts | **NO** |
| Runner images reproducible | **NO** — there is no lockfile for either runner image and the Dockerfiles run `npm install`, not `npm ci`, so the transitive dependency tree is resolved at build time |
| Runner dependencies monitored for CVEs | **NO** — `dependabot.yml` covers cargo, `/apps/web`, GitHub Actions, and runner *base images*, but has no npm entry for either runner directory |
| Third-party GitHub Actions pinned by commit SHA | **NO** — all float on mutable major tags in a job holding `packages: write` |
| Release publishing gated on tests | **NO** — ungated by deliberate choice; the Release PR's own CI is the last checkpoint |

This table is deliberately blunt. The code that runs *inside the sandbox*, beside
the workspace, is the least verifiable artifact fluidbox ships, and that is a
mismatch with a product whose stated promise is containment and accountability.
It is unchanged in this candidate and is the largest known gap. Ranked with
acceptance criteria as BLK-07 in [`../launch/launch-blockers.md`](../launch/launch-blockers.md).

---

## How to reproduce any row marked VALIDATED

```bash
just demo                 # keyless deterministic replay through the real gate
just gate-proof           # the permission gate, real image, no API key, no spend
bash deploy/compose-assertions.sh
bash scripts/demo-selftest.sh
cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace    # needs DATABASE_URL; use a throwaway database
node --test images/runner-lib/*.test.mjs
node --test images/replay-runner/runner/test/*.test.mjs
bash scripts/version-check.sh
helm lint deploy/helm/fluidbox
```

Full command-by-command evidence, with timings and outputs, is in
[`../reviews/release-candidate-readiness.md`](../reviews/release-candidate-readiness.md).
