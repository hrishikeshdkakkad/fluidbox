#!/usr/bin/env bash
# Provision the fluidbox Neon project and wire the DIRECT connection string
# into .env (written automatically when DATABASE_URL is still the placeholder;
# printed otherwise so an existing value is never clobbered).
#
# Usage: ./scripts/neon-setup.sh [project-name]
# Requires: node/npx. Authenticates via browser OAuth on first use.
# If your account belongs to multiple orgs, set NEON_ORG_ID.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT_NAME="${1:-fluidbox}"
NEON="npx -y neonctl@latest"
ORG_FLAG=()
[ -n "${NEON_ORG_ID:-}" ] && ORG_FLAG=(--org-id "$NEON_ORG_ID")

echo "→ checking neonctl auth…"
if ! $NEON projects list "${ORG_FLAG[@]}" -o json >/dev/null 2>&1; then
  echo "→ not authenticated (or org selection needed); trying browser OAuth…"
  $NEON auth
fi

# `projects list -o json` returns a top-level array.
EXISTING_ID=$($NEON projects list "${ORG_FLAG[@]}" -o json | node -e "
  let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{
    const j=JSON.parse(d);
    const all=Array.isArray(j)?j:[...(j.projects||[]),...(j.shared_projects||[])];
    const p=all.find(p=>p.name==='$PROJECT_NAME');
    process.stdout.write(p?p.id:'');
  })")

if [ -z "$EXISTING_ID" ]; then
  echo "→ creating Neon project '$PROJECT_NAME'…"
  EXISTING_ID=$($NEON projects create --name "$PROJECT_NAME" "${ORG_FLAG[@]}" -o json | node -e "
    let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{
      const j=JSON.parse(d);
      process.stdout.write((j.project||j).id);
    })")
else
  echo "→ project '$PROJECT_NAME' already exists ($EXISTING_ID)"
fi

echo "→ fetching DIRECT connection string (non-pooled — required for sqlx + LISTEN/NOTIFY)…"
DIRECT_URL=$($NEON connection-string --project-id "$EXISTING_ID")

case "$DIRECT_URL" in
  *-pooler*) echo "ERROR: got a pooled connection string; fluidbox needs the direct endpoint." >&2; exit 1;;
esac

current=""
[ -f "$ROOT/.env" ] && current=$(grep -m1 '^DATABASE_URL=' "$ROOT/.env" | cut -d= -f2- || true)
case "$current" in
  ""|*ep-xxx*)
    if [ -f "$ROOT/.env" ]; then
      node -e "
        const fs = require('fs'), path = '$ROOT/.env', url = process.argv[1];
        const src = fs.readFileSync(path, 'utf8');
        const out = /^DATABASE_URL=/m.test(src)
          ? src.replace(/^DATABASE_URL=.*$/m, 'DATABASE_URL=' + url)
          : src + '\nDATABASE_URL=' + url + '\n';
        fs.writeFileSync(path, out);
      " "$DIRECT_URL"
      echo "→ wrote DATABASE_URL into .env"
    else
      echo
      echo "DATABASE_URL=$DIRECT_URL"
      echo
      echo "No .env yet — run 'just setup' first, or put that line into .env yourself."
    fi
    ;;
  *)
    echo
    echo "DATABASE_URL=$DIRECT_URL"
    echo
    echo ".env already has a DATABASE_URL you set — left untouched. Paste the line above to switch."
    ;;
esac
