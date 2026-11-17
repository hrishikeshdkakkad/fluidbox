#!/usr/bin/env bash
# Refuses any tracked Terraform plan or state, whatever it is named.
#
# A plan is not a build artifact: `terraform plan -out=X` writes a zip whose
# `tfstate` member is a full state snapshot, and state holds every generated
# secret in plaintext (database passwords, the admin token, the sealing keys).
# Committing one to a public repository publishes those values.
#
# Two checks, because either alone has a hole:
#   1. by NAME   - the conventional spellings (`*.tfplan`, `tfplan`,
#                  `*.tfstate*`, `.terraform/`);
#   2. by CONTENT - any tracked zip that carries a `tfstate` member, so a plan
#                  written as `-out=whatever.bin` is still caught.
#
# .gitignore keeps these out of `git add .`; this keeps them out of `git add -f`
# and out of any ignore rule someone narrows later. Run by CI and `just check`.
set -euo pipefail

# FAIL CLOSED. Neither `cd "$(git …)"` nor `done < <(git …)` propagates a git
# failure under `set -e`, so an unreadable repository used to produce an empty
# file list and a cheerful "ok". Every git call is checked explicitly instead.
root="$(git rev-parse --show-toplevel)" || {
  echo "error: not inside a readable git work tree; refusing to report ok" >&2
  exit 2
}
cd "$root"

list="$(mktemp)"
trap 'rm -f "$list"' EXIT
git ls-files -z >"$list" || {
  echo "error: git ls-files failed; refusing to report ok" >&2
  exit 2
}
if [ ! -s "$list" ]; then
  echo "error: git ls-files returned no tracked files; refusing to report ok" >&2
  exit 2
fi

found=()

while IFS= read -r -d '' path; do
  case "$path" in
    *.tfplan | tfplan | */tfplan | *.tfstate | *.tfstate.* | .terraform/* | */.terraform/*)
      found+=("$path (name)")
      continue
      ;;
  esac
  # Content check: only files that start with the zip magic ("PK" = 50 4b) are
  # opened. The magic is read as HEX via od, never as raw bytes: bash cannot
  # hold a NUL, and byte tools choke on invalid UTF-8 under a UTF-8 locale.
  [ -f "$path" ] || continue
  if [ "$(LC_ALL=C od -An -tx1 -N2 "$path" 2>/dev/null | tr -d ' \n')" = "504b" ] &&
    unzip -Z1 "$path" 2>/dev/null | grep -qxE 'tfstate(-prev)?'; then
    found+=("$path (zip with a tfstate member)")
  fi
done <"$list"

if [ "${#found[@]}" -gt 0 ]; then
  echo "error: tracked Terraform plan/state files - these contain plaintext secrets:" >&2
  printf '  %s\n' "${found[@]}" >&2
  echo "Remove them with 'git rm --cached <file>', then treat every secret in that" >&2
  echo "state as exposed and rotate it." >&2
  exit 1
fi

echo "ok: no Terraform plan or state files are tracked"
