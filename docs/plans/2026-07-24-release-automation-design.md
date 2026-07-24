# Release automation design

**Status:** design + implementation, 2026-07-24. Supersedes the fully manual release process used for `v0.1.0`–`v0.3.0`.

## The problem, stated precisely

Every in-repo version field sat at `0.1.0` from the initial release through `v0.3.0` — two releases of drift that nobody noticed.

This was not carelessness. `.github/workflows/release.yml` derives the published version from the git tag (`VERSION="${GITHUB_REF_NAME#v}"`, then `helm package --version "$VERSION" --app-version "$VERSION"`), so **everything published was correct** while the repo's own manifests were wrong. The fields had no consumer that could fail.

Two consumers did read them, quietly:

- `crates/fluidbox-server/src/broker.rs` sends `clientInfo.version: env!("CARGO_PKG_VERSION")` on every upstream MCP `initialize` — third-party servers were told fluidbox was `0.1.0`.
- `helm install ./deploy/helm/fluidbox` from a checkout rendered `0.1.0` image refs.

**Governing rule adopted here: a version field that nothing validates is a comment, and comments rot.** The fix is therefore not "bump more carefully" but (a) reduce the number of independent copies, and (b) make CI fail when the survivors disagree.

## Decisions

| Decision | Choice | Why |
|---|---|---|
| Version source | release-please, inferred from Conventional Commits | 54/60 recent commits already conform; no habit change required |
| Changelog | Generated from commits | Owner's explicit choice, accepting loss of hand-written narrative. The Release PR remains editable if prose is wanted on a given release. |
| Pre-1.0 semantics | `bump-minor-pre-major: true` | A `feat` yields `0.3.0` → `0.4.0`; breaking changes stay minor while below 1.0 |
| Versioning granularity | Single lockstep version across all 10 crates, 3 npm packages, and the chart | Matches how artifacts already ship: one tag, one image tag for all five images |
| Publish gate | None — merging the Release PR publishes | Owner's explicit choice. The Release PR's own CI is therefore the sole checkpoint; the drift guard below runs there. |
| Trigger bridge | `workflow_call`, not a PAT | See below |
| README/guide versions | Collapse to one annotated `FLUIDBOX_VERSION` assignment | Fewer copies beats more automation; also better copy-paste UX |
| Runner JS `clientInfo` | Annotate now, derive from `package.json` later | Deriving is correct but changes sandbox payload code; that belongs in its own PR |

## The trigger bridge (the load-bearing part)

GitHub does not start workflow runs from events created with the repository's `GITHUB_TOKEN`. The rule exists to prevent a workflow from triggering itself indefinitely.

`release.yml` previously triggered on `push: tags: ["v*"]`. release-please creates its tag with `GITHUB_TOKEN`, so under naive automation the tag and GitHub Release would appear and **no images would ever build** — with nothing failing to signal it. The `v0.3.0` release worked only because a human pushed the tag.

Two bridges exist. We take the second:

1. **Give the bot a non-default credential** (PAT or GitHub App). Works, but introduces a secret that expires silently and breaks releases with no warning.
2. **Have the bot call the publish workflow directly.** `release.yml` becomes a reusable `workflow_call` workflow; `release-please.yml` invokes it when `release_created` is true. No secret, no expiry.

### Consequent changes inside `release.yml`

Both are mandatory and coupled — doing one without the other reintroduces the bug the file's own comments warn about.

- **Version source.** `GITHUB_REF_NAME` is `main` under `workflow_call`, so `VERSION` comes from `inputs.version`. The existing SemVer validation is retained and now guards that input.
- **Image tagging.** `docker/metadata-action`'s `type=semver` extracts a version *from the git ref* and emits nothing when the ref is not a tag. Called from a non-tag context it would publish `:latest`-only images while the chart references `:0.4.0` — an `ImagePullBackOff` in a user's cluster, with a green workflow. It becomes `type=raw,value=${{ inputs.version }}`.

The tag-push trigger is **removed** rather than kept alongside. Two entry points computing the version by different routes is the same disease as the original drift; one path cannot diverge from itself. Manual publishes remain available via `workflow_dispatch` with an explicit version.

## Version propagation

release-please writes one computed version into every site:

| Site | Mechanism |
|---|---|
| `Cargo.toml` (workspace) + `Cargo.lock` | native `rust` release type |
| `apps/web/package.json` | `extra-files` type `json`, `$.version` |
| `images/sandbox-runner/runner/package.json` | `extra-files` type `json`, `$.version` |
| `images/codex-runner/runner/package.json` | `extra-files` type `json`, `$.version` |
| `deploy/helm/fluidbox/Chart.yaml` | `extra-files` type `yaml`, `$.version` and `$.appVersion` |
| 5× runner JS `clientInfo` strings | generic updater, `x-release-please-version` annotation |
| `README.md`, `docs/guides/kubernetes.md` | generic updater on a single `FLUIDBOX_VERSION` assignment each |

The README and guide previously hardcoded `--version 0.3.0` inside a line-continued `helm install`, where an inline annotation would break the shell continuation. They now read:

```bash
FLUIDBOX_VERSION=0.3.0 # x-release-please-version
helm install fluidbox oci://ghcr.io/hrishikeshdkakkad/charts/fluidbox \
  --version "$FLUIDBOX_VERSION" \
```

This removes two hardcoded copies and lets a reader set one variable.

## Drift guard

`scripts/version-check.sh` treats `[workspace.package] version` in `Cargo.toml` as canonical and asserts every other site matches, printing the exact mismatch and fix per failure — the established `just doctor` idiom. Wired into CI as its own fast job and into `just check`.

The guard is deliberately independent of release-please. If a config entry is wrong, an `extra-files` path is renamed, or someone hand-edits a manifest, the guard fails on the Release PR — which, given the ungated publish, is the last checkpoint before public artifacts.

## Verification plan

The automation cannot be proven correct by unit tests; it is proven by these, in order:

1. `scripts/version-check.sh` passes on the current tree, and fails when a version is deliberately mutated (mutation-tested, not assumed).
2. `actionlint` (or equivalent parse) accepts both workflows.
3. The first release-please run opens a Release PR whose diff touches **every** site in the table above. If any site is missing, the config — not the guard — is wrong, and the guard would have caught it at merge.
4. The first automated publish is compared against `v0.3.0`'s published tag set: five images each carrying `:X.Y.Z` and `:latest`, plus the OCI chart at `X.Y.Z`.

Step 3 is the real acceptance gate; steps 1–2 are cheap preconditions.

## Residuals

- **The generated changelog loses narrative.** Accepted by the owner. The `v0.3.0` entry's explanation of the four-object authority model is the kind of content commit subjects cannot carry. Revisit after the first generated release.
- **Merging the Release PR publishes irreversibly.** Accepted by the owner. Rollback means publishing a newer version, never removing the bad one. The Release PR's CI is the only checkpoint.
- **release-please's Rust workspace handling is verified empirically, not by us.** Step 3 exists precisely because `Cargo.lock`'s ten member entries are the most likely thing for the config to miss.
- **Runner JS still holds hardcoded version strings.** Annotated now; deriving from `package.json` is the durable fix and is deferred to its own PR.
