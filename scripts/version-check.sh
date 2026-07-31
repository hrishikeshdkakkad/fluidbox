#!/usr/bin/env bash
# Version drift guard.
#
# Every in-repo version field sat at 0.1.0 from the first release through
# v0.3.0 -- two releases of drift nobody noticed -- because release.yml
# derives the PUBLISHED version from the git tag, so the artifacts were
# always right while the manifests lied. A version field that nothing
# validates is a comment, and comments rot.
#
# This is that missing validator. `[workspace.package] version` in
# Cargo.toml is canonical; every other site must agree.
#
# release-please keeps these in sync automatically, so a failure here means
# one of: its config lost a path, a file moved, or someone hand-edited. All
# three are worth failing a build over -- especially because merging the
# Release PR publishes to GHCR with no further gate, making the Release PR's
# CI the last checkpoint before public, effectively permanent artifacts.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

fail=0
canonical=""

# Read `version = "X.Y.Z"` from the [workspace.package] table specifically --
# not the first `version =` in the file, which would match a dependency.
canonical=$(awk '
  /^\[workspace\.package\]/ { in_wp = 1; next }
  /^\[/                     { in_wp = 0 }
  in_wp && /^version[[:space:]]*=/ {
    gsub(/^version[[:space:]]*=[[:space:]]*"/, ""); gsub(/".*$/, ""); print; exit
  }
' Cargo.toml)

if [[ -z "$canonical" ]]; then
  echo "FATAL: no [workspace.package] version in Cargo.toml" >&2
  exit 1
fi

echo "canonical version (Cargo.toml [workspace.package]): $canonical"
echo

# check <label> <actual> <file> <how-to-fix>
check() {
  local label="$1" actual="$2" file="$3" fix="$4"
  if [[ "$actual" != "$canonical" ]]; then
    printf 'MISMATCH  %-34s %s (expected %s)\n' "$label" "${actual:-<missing>}" "$canonical"
    printf '          %s\n          fix: %s\n\n' "$file" "$fix"
    fail=1
  else
    printf 'ok        %-34s %s\n' "$label" "$actual"
  fi
}

json_version() {
  python3 -c "import json,sys; print(json.load(open(sys.argv[1])).get('version',''))" "$1" 2>/dev/null || echo ""
}

# --- version.txt ------------------------------------------------------------
# release-please's `simple` strategy ALWAYS writes a version file (default
# `version.txt`, and there is no option to skip it -- see strategies/simple.js).
# We use `simple` because the `rust` strategy cannot handle this workspace: it
# rewrites `package.version` in every member (ours inherit via
# `version.workspace = true`) and then demands the ROOT be a package manifest
# (ours is a virtual workspace). So version.txt is not cruft we tolerate, it is
# a site release-please owns -- which means it can drift, which means it gets
# checked like every other site.
check "version.txt" \
  "$(tr -d '[:space:]' < version.txt 2>/dev/null)" \
  "version.txt" \
  "release-please simple strategy version file"

# --- npm packages -----------------------------------------------------------
check "apps/web" \
  "$(json_version apps/web/package.json)" \
  "apps/web/package.json" \
  "release-please extra-files json \$.version"

check "sandbox-runner pkg" \
  "$(json_version images/sandbox-runner/runner/package.json)" \
  "images/sandbox-runner/runner/package.json" \
  "release-please extra-files json \$.version"

check "codex-runner pkg" \
  "$(json_version images/codex-runner/runner/package.json)" \
  "images/codex-runner/runner/package.json" \
  "release-please extra-files json \$.version"

# --- Helm chart -------------------------------------------------------------
# Both keys matter: `version` is the chart version, `appVersion` is what the
# image defaults render from. release.yml overrides both at package time, so
# these only bind a local `helm install ./deploy/helm/fluidbox`.
check "Chart.yaml version" \
  "$(awk -F': *' '/^version:/ {print $2; exit}' deploy/helm/fluidbox/Chart.yaml)" \
  "deploy/helm/fluidbox/Chart.yaml" \
  "release-please extra-files yaml \$.version"

check "Chart.yaml appVersion" \
  "$(awk -F': *' '/^appVersion:/ {gsub(/"/,"",$2); print $2; exit}' deploy/helm/fluidbox/Chart.yaml)" \
  "deploy/helm/fluidbox/Chart.yaml" \
  "release-please extra-files yaml \$.appVersion"

# --- Cargo.lock -------------------------------------------------------------
# Workspace members inherit via `version.workspace = true`, so a stale lock
# means someone edited Cargo.toml without re-resolving.
lock_bad=$(awk -v want="$canonical" '
  /^name = "/ { name = $3; gsub(/"/, "", name) }
  /^version = "/ {
    v = $3; gsub(/"/, "", v)
    if ((name ~ /^fluidbox-/ || name == "workspaced") && v != want) print name "=" v
  }
' Cargo.lock | sort -u)

if [[ -n "$lock_bad" ]]; then
  printf 'MISMATCH  %-34s %s\n' "Cargo.lock members" "$(echo "$lock_bad" | tr '\n' ' ')"
  printf '          Cargo.lock\n          fix: cargo metadata --format-version 1 >/dev/null\n\n'
  fail=1
else
  printf 'ok        %-34s all workspace members\n' "Cargo.lock members"
fi

# --- annotated generic sites ------------------------------------------------
# The file list comes from release-please's OWN config -- the plain-string
# entries in extra-files, which are the ones its generic updater rewrites by
# looking for the marker. Deriving the list rather than grepping the tree is
# the same principle this guard exists to enforce: one source of truth. Add a
# file to the config and it is covered here automatically; drop one and this
# correctly stops checking it. It also avoids matching prose that merely
# mentions the marker (this script, the design doc).
mapfile -t generic_files < <(python3 -c "
import json
cfg = json.load(open('release-please-config.json'))
for f in cfg['packages']['.']['extra-files']:
    if isinstance(f, str):
        print(f)
")

if [[ "${#generic_files[@]}" -eq 0 ]]; then
  echo "MISMATCH  generic extra-files                <none declared>"
  echo "          release-please-config.json declares no plain-string extra-files"
  fail=1
fi

for f in "${generic_files[@]}"; do
  if [[ ! -f "$f" ]]; then
    printf 'MISMATCH  %-34s %s\n' "extra-file missing" "$f"
    printf '          declared in release-please-config.json but not on disk\n'
    printf '          fix: correct the path, or drop the entry\n\n'
    fail=1
    continue
  fi

  hits=$(grep -n "x-release-please-version" "$f" || true)
  if [[ -z "$hits" ]]; then
    printf 'MISMATCH  %-34s %s\n' "no marker" "$f"
    printf '          declared as a generic extra-file but carries no\n'
    printf '          x-release-please-version marker, so it will NEVER be bumped\n'
    printf '          fix: annotate the version line, or drop the entry\n\n'
    fail=1
    continue
  fi

  while IFS= read -r hit; do
    [[ -z "$hit" ]] && continue
    lineno="${hit%%:*}"
    # First semver on the annotated line is the one release-please rewrites.
    #
    # The prerelease suffix is part of the version, not noise. Without the
    # optional `-…` group this guard cannot express a release CANDIDATE at all:
    # a canonical of `0.4.0-rc.1` extracted `0.4.0` from every annotated site
    # and reported all six as MISMATCH, so `just check` and the CI version-check
    # job failed on any `-rc`/`-beta` version — the exact versions a release is
    # supposed to be staged through. The charset matches the SemVer gate in
    # release.yml's chart job, so the two agree on what is publishable.
    found=$(sed -E 's/.*[^0-9]([0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?).*/\1/' <<<"${hit#*:}")
    if [[ "$found" != "$canonical" ]]; then
      printf 'MISMATCH  %-34s %s\n' "annotated site" "$found"
      printf '          %s:%s\n          fix: set to %s\n\n' "$f" "$lineno" "$canonical"
      fail=1
    else
      printf 'ok        %-34s %s:%s\n' "annotated site" "$f" "$lineno"
    fi
  done <<<"$hits"
done

# --- release-please manifest ------------------------------------------------
# The manifest is release-please's memory of the last release. If it drifts
# from the tree, the next computed version is wrong.
manifest=$(python3 -c "import json;print(json.load(open('.release-please-manifest.json'))['.'])" 2>/dev/null || echo "")
check "release-please manifest" "$manifest" ".release-please-manifest.json" \
  "set to the last RELEASED version"

echo
if [[ "$fail" -ne 0 ]]; then
  echo "FAILED: version drift detected. See fixes above." >&2
  exit 1
fi
echo "PASS: all version sites agree at $canonical"
