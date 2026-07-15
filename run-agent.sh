#!/usr/bin/env bash
# Run a fluidbox agent by NAME via the admin API.
#   ./run-agent.sh <agent-name> [task text...]
# Reads FLUIDBOX_ADMIN_TOKEN from ./.env; base URL = $FLUIDBOX_BASE or http://127.0.0.1:8787
set -euo pipefail
if [ $# -lt 1 ]; then
  echo "usage: $0 <agent-name> [task text...]" >&2
  echo "example: $0 clouflare-mcp-test-resource \"use the cloudflare MCP to create+delete a test R2 bucket\"" >&2
  exit 1
fi
AGENT="$1"; shift
TASK="${*:-Use the cloudflare MCP to create a disposable test resource, verify it, then delete it; report the results.}"
BASE="${FLUIDBOX_BASE:-http://127.0.0.1:8787}"
ADMIN="$(grep -E '^FLUIDBOX_ADMIN_TOKEN=' .env | head -1 | cut -d= -f2- | sed 's/^"//;s/"$//')"
BODY="$(AGENT="$AGENT" TASK="$TASK" python3 -c 'import os,json;print(json.dumps({"agent":os.environ["AGENT"],"task":os.environ["TASK"]}))')"
RES="$(curl -s -X POST -H "Authorization: Bearer $ADMIN" -H "Content-Type: application/json" -d "$BODY" "$BASE/v1/sessions")"
SID="$(printf '%s' "$RES" | grep -oiE '[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[0-9a-f]{4}-[0-9a-f]{12}' | head -1)"
if [ -n "$SID" ]; then
  echo "started agent '$AGENT' -> session $SID"
  echo "watch/approve: http://localhost:3000/sessions/$SID"
else
  echo "failed: $RES"
fi
