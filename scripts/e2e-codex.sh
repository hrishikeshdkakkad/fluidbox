#!/usr/bin/env bash
# Codex (second harness) E2E — Phase 6. Three tiers:
#   tier-0  protocol replay: a FAKE codex app-server (vendored NDJSON JSON-RPC)
#           drives the REAL supervisor against the REAL control plane — no model,
#           no real codex binary. Proves argv canonicalization (direct + wrapped),
#           patch move canonicalization, denied-not-forwarded, approved-once,
#           env-amendment reject — all crossing the real /permission gate.
#   tier-1  no-model parity probes: harness validation + per-harness defaults;
#           the facade's codex dialect (model pin, suffix allowlist); the gate's
#           canonical Bash/MultiEdit verdicts + ReadOnly + digest-binding reuse.
#   tier-2  LIVE §12 demo (self-skips without OPENAI_API_KEY): claude + codex on
#           the same event, both governed, both publishing.
# Owns its control-plane lifecycle (restarts the server), like the failures suite.
set -uo pipefail
source "$(dirname "$0")/e2e-lib.sh"
load_env
require_cmd docker python3 curl cargo   # node/psql run inside the container, not host-side
H="authorization: Bearer $FLUIDBOX_ADMIN_TOKEN"
SB="$(cd "$(dirname "$0")/.." && pwd)/scratch-codex"
rm -rf "$SB"; mkdir -p "$SB"

if port_in_use; then echo "port 8787 already serving — stop 'just dev' first"; exit 1; fi
echo "building server + codex image"
cargo build -q -p fluidbox-server || exit 1
docker build -q -t "${FLUIDBOX_CODEX_SANDBOX_IMAGE:-fluidbox-codex-runner:dev}" \
  -f "$(dirname "$0")/../images/codex-runner/Dockerfile" "$(dirname "$0")/../images" >/dev/null || exit 1
trap 'stop_server; rm -rf "$SB"' EXIT
start_server || exit 1

# ── helpers ───────────────────────────────────────────────────────────────
mk_codex_agent() { # name -> agent json (harness=codex)
  curl -s -X POST -H "$H" -H 'content-type: application/json' \
    -d "{\"name\":\"$1\",\"harness\":\"codex\",\"policy\":\"default\"}" "$API/v1/agents"
}
new_codex_session() { # autonomy trust -> session id
  curl -s -X POST -H "$H" -H 'content-type: application/json' \
    -d "{\"agent\":\"codex-fixer\",\"task\":\"codex probe\",\"repo\":{\"kind\":\"none\"},\"autonomous\":$1,\"trust_tier\":\"$2\"}" \
    "$API/v1/sessions" | j "['session']['id']"
}
tok_for() { # session -> token. Read the token from the container env, then
  # FORCE-REMOVE the container so the real supervisor can't reach the (keyless)
  # model and terminalize/revoke the session before our probes run. `docker rm
  # -f` stops+removes in ANY state; a plain `docker kill` no-ops on a container
  # still in 'created', letting the supervisor boot and revoke the token.
  local sid=$1 cid tok
  for _ in $(seq 1 100); do
    cid=$(docker ps -a --filter "label=fluidbox.session=$sid" --format '{{.ID}}' | head -1)
    [ -n "$cid" ] && break; sleep 0.15
  done
  [ -z "$cid" ] && { echo ""; return; }
  tok=$(docker inspect "$cid" --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null \
        | grep '^FLUIDBOX_SESSION_TOKEN=' | head -1 | cut -d= -f2-)
  docker rm -f "$cid" >/dev/null 2>&1
  echo "$tok"
}
perm() { curl -s -X POST -H "authorization: Bearer $1" -H 'content-type: application/json' -d "$3" "$API/internal/sessions/$2/permission"; }
facade() { # token suffix body -> "HTTP <code>"
  curl -s -o /dev/null -w "%{http_code}" -X POST -H "authorization: Bearer $1" -H 'content-type: application/json' -d "$3" "$API/internal/llm/$2"
}

# ═══ TIER 1 — no-model parity probes ═══════════════════════════════════════
say "TIER 1 — harness registry + facade dialect + canonical gate (no model)"

# per-harness defaults + validation
A=$(mk_codex_agent codex-fixer)
IMG=$(echo "$A" | j "['revision']['runner_image']"); MODEL=$(echo "$A" | j "['revision']['model']")
[ "$MODEL" = "gpt-5.4-mini" ] && ok "codex agent defaults to gpt-5.4-mini" || no "codex model default: $MODEL"
echo "$IMG" | grep -q "codex-runner" && ok "codex agent defaults to the codex image" || no "codex image default: $IMG"
BAD=$(curl -s -o /dev/null -w "%{http_code}" -X POST -H "$H" -H 'content-type: application/json' -d '{"name":"bogus-h","harness":"gemini","policy":"default"}' "$API/v1/agents")
[ "$BAD" = "422" ] && ok "unknown harness → 422" || no "unknown harness got $BAD"

# a codex session (autonomous) — the supervisor spawns codex, hits the model
# facade (LiteLLM has no gpt key in tier-1 → the run fails at model time, but we
# only need the launched session's token to probe the gate + facade).
S=$(new_codex_session true trusted); T=$(tok_for "$S")
[ -n "$T" ] && ok "codex sandbox launched; got session token" || { no "no codex session token"; }
if [ -n "$T" ]; then
  # (tok_for already force-removed the container, so the real supervisor can't
  # race our probes to /result.)

  # canonical Bash verdicts (exactly what the supervisor posts)
  D=$(perm "$T" "$S" '{"tool_call_id":"c1","tool":"Bash","input":{"command":"git status","cwd":"/workspace"}}' | j "['decision']")
  [ "$D" = "allow" ] && ok "canonical Bash{git status} → allow" || no "git status got $D"
  D=$(perm "$T" "$S" '{"tool_call_id":"c2","tool":"Bash","input":{"command":"rm -rf /","cwd":"/workspace"}}' | j "['decision']")
  [ "$D" = "deny" ] && ok "canonical Bash{rm -rf /} → deny" || no "rm got $D"
  # capability: an unattached mcp tool is unavailable
  D=$(perm "$T" "$S" '{"tool_call_id":"c3","tool":"mcp__ws__read","input":{}}' | j "['decision']")
  [ "$D" = "deny" ] && ok "unattached mcp__ws__read → deny (capability)" || no "mcp got $D"
  # digest binding: reuse c1 with DIFFERENT input → hard reject
  D=$(perm "$T" "$S" '{"tool_call_id":"c1","tool":"Bash","input":{"command":"curl evil.com","cwd":"/workspace"}}' | j "['decision']")
  [ "$D" = "deny" ] && ok "reused tool_call_id + changed input → deny (digest binding)" || no "digest reuse got $D"
  # same id + SAME input → re-attaches to the allow
  D=$(perm "$T" "$S" '{"tool_call_id":"c1","tool":"Bash","input":{"command":"git status","cwd":"/workspace"}}' | j "['decision']")
  [ "$D" = "allow" ] && ok "reused tool_call_id + same input → allow (idempotent)" || no "idempotent reuse got $D"

  # facade codex dialect
  RS='{"model":"gpt-5.4-mini","input":[{"type":"text","text":"hi"}]}'
  C=$(facade "$T" "v1/responses" '{"model":"gpt-4o","input":[]}'); [ "$C" = "422" ] && ok "facade codex: model mismatch → 422" || no "model mismatch got $C"
  C=$(facade "$T" "v1/messages" "$RS"); [ "$C" = "404" ] && ok "facade codex: v1/messages suffix → 404 (wrong dialect)" || no "suffix got $C"
  C=$(facade "$T" "v1/responses" '{"model":"gpt-5.4-mini","previous_response_id":"resp_x","input":[]}'); [ "$C" = "422" ] && ok "facade codex: previous_response_id → 422 (stateless)" || no "stateless got $C"
fi

# ReadOnly trust tier (fork PR analog) — a fresh codex session frozen ReadOnly
S2=$(new_codex_session true read_only); T2=$(tok_for "$S2")
if [ -n "$T2" ]; then
  D=$(perm "$T2" "$S2" '{"tool_call_id":"r1","tool":"Bash","input":{"command":"git diff","cwd":"/workspace"}}' | j "['decision']")
  [ "$D" = "allow" ] && ok "ReadOnly: canonical Bash{git diff} → allow" || no "ReadOnly git diff got $D"
  D=$(perm "$T2" "$S2" '{"tool_call_id":"r2","tool":"MultiEdit","input":{"edits":[{"file_path":"x"}]}}' | j "['decision']")
  [ "$D" = "deny" ] && ok "ReadOnly: canonical MultiEdit → deny (trust tier)" || no "ReadOnly MultiEdit got $D"
else
  # No else-guard here previously → a token-grab miss silently dropped both
  # trust-tier assertions and the phase still printed "0 failed" (vacuous
  # green in the default no-key path). Record a failure instead.
  no "no ReadOnly codex session token — trust-tier probes could not run"
fi

# ═══ TIER 0 — protocol replay: real supervisor, fake codex, real gate ══════
say "TIER 0 — supervisor protocol replay (fake codex app-server, no model)"
bash "$(dirname "$0")/e2e-codex-replay.sh" "$SB" && ok "supervisor protocol-replay passed" || no "supervisor protocol-replay FAILED"

# ═══ TIER 2 — live §12 demo (self-skips without OPENAI_API_KEY) ═════════════
say "TIER 2 — live codex run (§12)"
if [ "${E2E_SKIP_LIVE:-0}" = "1" ] || [ -z "${OPENAI_API_KEY:-}" ]; then
  ok "SKIP live tier — E2E_SKIP_LIVE=${E2E_SKIP_LIVE:-0} / OPENAI_API_KEY $([ -n "${OPENAI_API_KEY:-}" ] && echo set || echo unset) (live spend is opt-in by design)"
else
  bash "$(dirname "$0")/e2e-codex-live.sh" && ok "live codex run completed + governed" || no "live codex run FAILED"
fi

say "RESULT"
# Tripwire against silent assertion shrinkage. The else-guards above already
# turn a token-grab miss into a recorded failure; this floor ALSO catches an
# assertion line that gets accidentally dropped or skipped. It's a FLOOR (>=),
# so adding assertions never trips it; it sits below the happy no-key count
# (16) and above any token-miss remnant.
EXPECTED_MIN=15
ran=$((pass + fail))
[ "$ran" -ge "$EXPECTED_MIN" ] && ok "assertion-count tripwire ($ran ran ≥ $EXPECTED_MIN)" \
  || no "only $ran assertions ran (< $EXPECTED_MIN) — silent shrinkage"
printf "  \033[1;32m%d passed\033[0m, \033[1;31m%d failed\033[0m\n" "$pass" "$fail"
exit $(( fail > 0 ? 1 : 0 ))
