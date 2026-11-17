#!/usr/bin/env bash
# Rotate the GENERATED production credentials: the admin token, the LiteLLM
# master key, both Cloud SQL passwords (with their DATABASE_URL secrets), and the
# static KEK. Terraform mints the initial values; rotating them is this script's
# job, because Terraform deliberately never replaces a generated secret version
# (secrets.tf ignore_changes) and never resets a SQL password (sql.tf).
#
#   scripts/cloud/gcp-rotate-credentials.sh                     # report only
#   scripts/cloud/gcp-rotate-credentials.sh --rotate admin-token,litellm-master-key,sql
#   scripts/cloud/gcp-rotate-credentials.sh --rotate kek        # stage a KEK rotation
#   scripts/cloud/gcp-rotate-credentials.sh --finish-kek        # after the rotation boot
#   ... add --apply to any of the above to actually change something.
#
# Without --apply it only reads and says what it would do. Values are generated
# here, passed to gcloud and the Cloud SQL API on STDIN, and never printed or put
# on a command line (where `ps` would show them).
#
# The KEK takes two runs with a deploy between them (docs/hosted/kms-operations.md
# section 4):
#   1. --rotate kek --apply     copies the current KEK into
#                               fluidbox-kms-previous-static-kek and adds a NEW
#                               version of fluidbox-kms-static-kek.
#   2. run the deploy workflow by hand with
#      kek_rotation_previous_ref=fluidbox-kms-previous-static-kek, and check the
#      server log for "KEK rotation complete" (and the kms.kek_rotated audit row).
#   3. --finish-kek --apply     destroys the previous-KEK copy and DISABLES the old
#                               KEK version. Disabled, not destroyed: if step 2 did
#                               not really finish, the old key is still there to
#                               re-enable. Destroy it by hand once you are sure.
#   4. deploy normally (a push never sets the rotation input).
#
# Retired versions of the other secrets are DESTROYED after the new version is
# added: they were rotated because they leaked, and a superseded version that can
# still be read is still a leaked credential. Running pods keep the values they
# started with, so restart them after a rotation.
set -euo pipefail

PROJECT="${GCP_PROJECT:-fluidbox-506603}"
SQL_INSTANCE="${SQL_INSTANCE:-fluidbox-pg}"
APPLY=0
ROTATE=""
FINISH_KEK=0

die() { echo "error: $*" >&2; exit 1; }
say() { printf '%s\n' "$*"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --apply) APPLY=1 ;;
    --rotate) shift; ROTATE="${1:-}"; [ -n "$ROTATE" ] || die "--rotate needs a list" ;;
    --finish-kek) FINISH_KEK=1 ;;
    --project) shift; PROJECT="${1:-}" ;;
    -h | --help) sed -n '2,35p' "$0"; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
  shift
done

for t in ${ROTATE//,/ }; do
  case "$t" in
    admin-token | litellm-master-key | sql | kek) ;;
    *) die "unknown --rotate target '$t' (known: admin-token, litellm-master-key, sql, kek)" ;;
  esac
done
if [ "$FINISH_KEK" = 1 ] && [[ ",$ROTATE," == *",kek,"* ]]; then
  die "--rotate kek and --finish-kek are separate runs with a deploy between them"
fi
command -v gcloud >/dev/null || die "gcloud is required"
command -v python3 >/dev/null || die "python3 is required"
command -v openssl >/dev/null || die "openssl is required"
gcloud auth print-access-token >/dev/null 2>&1 ||
  die "gcloud is not authenticated (gcloud auth login)"

wants() { [[ ",$ROTATE," == *",$1,"* ]]; }
mode() { [ "$APPLY" = 1 ] && echo "APPLY" || echo "dry-run"; }

# A random alphanumeric string of exactly $1 characters. Alphanumeric because the
# SQL passwords are embedded in a postgres:// URL (see sql.tf).
rand_alnum() {
  local out=""
  while [ "${#out}" -lt "$1" ]; do
    out+="$(openssl rand -base64 96 | tr -dc 'A-Za-z0-9')"
  done
  printf '%s' "${out:0:$1}"
}

enabled_versions() { # secret
  gcloud secrets versions list "$1" --project "$PROJECT" \
    --filter='state=ENABLED' --format='value(name.basename())'
}

# Add a version from STDIN; print the new version id.
add_version() { # secret  (value on stdin)
  gcloud secrets versions add "$1" --project "$PROJECT" --data-file=- \
    --format='value(name.basename())'
}

destroy_older() { # secret keep_version
  local v
  for v in $(enabled_versions "$1"); do
    [ "$v" = "$2" ] && continue
    gcloud secrets versions destroy "$v" --secret "$1" --project "$PROJECT" --quiet >/dev/null
    say "    destroyed $1 version $v"
  done
}

# Replace a secret's value: add the new version (stdin), then destroy every older
# enabled version.
replace_secret() { # secret  (value on stdin)
  local new
  new="$(add_version "$1")"
  [ -n "$new" ] || die "adding a version to $1 returned no version id"
  say "    added $1 version $new"
  destroy_older "$1" "$new"
}

report_secret() { # secret
  local n
  n="$(enabled_versions "$1" | grep -c . || true)"
  say "    $1: $n enabled version(s)"
}

say "project $PROJECT — $(mode)"

# ── admin token / LiteLLM master key ────────────────────────────────────────
if wants admin-token; then
  say "  admin token (fluidbox-admin-token)"
  report_secret fluidbox-admin-token
  if [ "$APPLY" = 1 ]; then
    rand_alnum 48 | replace_secret fluidbox-admin-token
  fi
fi

if wants litellm-master-key; then
  say "  LiteLLM master key (litellm-master-key)"
  report_secret litellm-master-key
  if [ "$APPLY" = 1 ]; then
    { printf 'sk-'; rand_alnum 40; } | replace_secret litellm-master-key
  fi
fi

# ── Cloud SQL passwords + their DATABASE_URL secrets ────────────────────────
# The password is set through the Cloud SQL Admin API with the JSON body on stdin
# and the bearer token in a 0600 header file, so neither appears in argv.
set_sql_password() { # user  (password on stdin)
  local hdr op
  hdr="$(mktemp)"
  chmod 600 "$hdr"
  printf 'Authorization: Bearer %s\n' "$(gcloud auth print-access-token)" >"$hdr"
  op="$(python3 -c 'import json,sys;print(json.dumps({"name":sys.argv[1],"password":sys.stdin.read()}))' "$1" |
    curl -sS --fail-with-body -X PUT -H @"$hdr" -H 'content-type: application/json' \
      --data-binary @- \
      "https://sqladmin.googleapis.com/v1/projects/$PROJECT/instances/$SQL_INSTANCE/users?name=$1" |
    python3 -c 'import json,sys;print(json.load(sys.stdin)["name"])')" || { rm -f "$hdr"; die "setting the $1 password failed"; }
  rm -f "$hdr"
  gcloud sql operations wait "$op" --project "$PROJECT" --timeout=300 >/dev/null
}

# Rewrite only the password inside a postgres URL. Line 1 = current URL, line 2 =
# new password; checks the user so a URL for the wrong database is refused.
swap_url_password() { # expected_user
  python3 -c '
import sys, urllib.parse as u
url, pw = sys.stdin.read().split("\n", 1)
p = u.urlsplit(url)
if p.username != sys.argv[1] or not p.hostname:
    sys.exit("refusing: the stored URL is not for user %r" % sys.argv[1])
host = p.hostname + (":%d" % p.port if p.port else "")
print(u.urlunsplit((p.scheme, "%s:%s@%s" % (p.username, u.quote(pw, safe=""), host), p.path, p.query, p.fragment)), end="")
' "$1"
}

rotate_sql() { # user url_secret
  local pw url
  say "  Cloud SQL user $1 + $2"
  report_secret "$2"
  # Prove the stored URL parses for this user BEFORE changing anything.
  url="$(gcloud secrets versions access latest --secret "$2" --project "$PROJECT")"
  printf '%s\n%s' "$url" "probe" | swap_url_password "$1" >/dev/null
  [ "$APPLY" = 1 ] || return 0
  pw="$(rand_alnum 32)"
  printf '%s' "$pw" | set_sql_password "$1"
  say "    set the $1 password"
  printf '%s\n%s' "$url" "$pw" | swap_url_password "$1" | replace_secret "$2"
  unset pw url
}

if wants sql; then
  rotate_sql fluidbox fluidbox-database-url
  rotate_sql litellm litellm-database-url
fi

# ── static KEK ──────────────────────────────────────────────────────────────
if wants kek; then
  say "  static KEK (fluidbox-kms-static-kek → fluidbox-kms-previous-static-kek)"
  report_secret fluidbox-kms-static-kek
  report_secret fluidbox-kms-previous-static-kek
  [ -z "$(enabled_versions fluidbox-kms-previous-static-kek)" ] ||
    die "fluidbox-kms-previous-static-kek already holds a version: a rotation is in progress. Finish it (--finish-kek) first"
  if [ "$APPLY" = 1 ]; then
    gcloud secrets versions access latest --secret fluidbox-kms-static-kek --project "$PROJECT" |
      add_version fluidbox-kms-previous-static-kek >/dev/null
    say "    copied the current KEK into fluidbox-kms-previous-static-kek"
    new="$(openssl rand -hex 32 | tr -d '\n' | add_version fluidbox-kms-static-kek)"
    say "    added fluidbox-kms-static-kek version $new (the NEW KEK)"
    say "  next: run the deploy workflow with kek_rotation_previous_ref=fluidbox-kms-previous-static-kek,"
    say "        confirm 'KEK rotation complete' in the server log, then run --finish-kek --apply"
  fi
fi

if [ "$FINISH_KEK" = 1 ]; then
  say "  finish the KEK rotation"
  report_secret fluidbox-kms-static-kek
  report_secret fluidbox-kms-previous-static-kek
  latest="$(gcloud secrets versions list fluidbox-kms-static-kek --project "$PROJECT" \
    --filter='state=ENABLED' --sort-by='~createTime' --limit=1 --format='value(name.basename())')"
  [ -n "$latest" ] || die "fluidbox-kms-static-kek has no enabled version"
  if [ "$APPLY" = 1 ]; then
    destroy_older fluidbox-kms-previous-static-kek ""
    for v in $(enabled_versions fluidbox-kms-static-kek); do
      [ "$v" = "$latest" ] && continue
      gcloud secrets versions disable "$v" --secret fluidbox-kms-static-kek --project "$PROJECT" --quiet >/dev/null
      say "    disabled fluidbox-kms-static-kek version $v (re-enable it if the rotation did not finish)"
    done
    say "  next: deploy normally (without kek_rotation_previous_ref)"
  fi
fi

[ "$APPLY" = 1 ] || say "dry-run: nothing changed (add --apply)"
