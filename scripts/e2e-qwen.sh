#!/usr/bin/env bash
# Qwen Code (third harness) E2E. Three tiers, mirroring the codex phase:
#   tier-0  protocol replay: a FAKE qwen CLI (vendored stream-json control
#           protocol) drives the REAL supervisor against the REAL control
#           plane — no model, no real qwen binary. Proves canonicalization
#           (Read/Bash incl. the bash -lc unwrap), the supervisor-side
#           fail-closed denies (cwd escape, empty command, unmapped tool),
#           and that sandbox MCP gates under its native name.
#   tier-1  no-model parity probes: harness registry defaults + validation;
#           the facade's chat-completions dialect (suffix allowlist, model
#           pin, legacy-functions reject); canonical gate verdicts + ReadOnly
#           + digest binding.
#   tier-2  LIVE run (self-skips without DASHSCOPE_API_KEY): a real qwen
#           agent end-to-end, incl. THE drift canary — a read must produce a
#           canonical Read tool.requested (permissions.ask interception
#           against the real pinned CLI).
# Owns its control-plane lifecycle (restarts the server), like the codex phase.
set -uo pipefail
source "$(dirname "$0")/e2e-lib.sh"
load_env
require_cmd docker python3 curl cargo
H="authorization: Bearer $FLUIDBOX_ADMIN_TOKEN"
SB="$(cd "$(dirname "$0")/.." && pwd)/scratch-qwen"
rm -rf "$SB"; mkdir -p "$SB"

if port_in_use; then echo "port 8787 already serving — stop 'just dev' first"; exit 1; fi
echo "building server + qwen image"
cargo build -q -p fluidbox-server || exit 1
docker build -q -t "${FLUIDBOX_QWEN_SANDBOX_IMAGE:-fluidbox-qwen-runner:dev}" \
  -f "$(dirname "$0")/../images/qwen-runner/Dockerfile" "$(dirname "$0")/../images" >/dev/null || exit 1
trap 'stop_server; rm -rf "$SB"' EXIT
start_server || exit 1

# ── helpers ───────────────────────────────────────────────────────────────
new_qwen_session() { # autonomy trust -> session id
  curl -s -X POST -H "$H" -H 'content-type: application/json' \
    -d "{\"agent\":\"qwen-fixer\",\"task\":\"qwen probe\",\"repo\":{\"kind\":\"none\"},\"autonomous\":$1,\"trust_tier\":\"$2\"}" \
    "$API/v1/sessions" | j "['session']['id']"
}
tok_for() { # session -> "tool-token llm-token". Read once, then FORCE-REMOVE
  # the container so the real supervisor can't reach the (keyless) model and
  # terminalize/revoke the session before our probes run.
  local sid=$1 cid tok
  for _ in $(seq 1 100); do
    cid=$(docker ps -a --filter "label=fluidbox.session=$sid" --format '{{.ID}}' | head -1)
    [ -n "$cid" ] && break; sleep 0.15
  done
  [ -z "$cid" ] && { echo ""; return; }
  local envdump llm
  envdump=$(docker inspect "$cid" --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null)
  tok=$(echo "$envdump" | grep '^FLUIDBOX_TOOL_TOKEN=' | head -1 | cut -d= -f2-)
  llm=$(echo "$envdump" | grep '^FLUIDBOX_LLM_TOKEN=' | head -1 | cut -d= -f2-)
  docker rm -f "$cid" >/dev/null 2>&1
  echo "$tok $llm"
}
perm() { curl -s -X POST -H "authorization: Bearer $1" -H 'content-type: application/json' -d "$3" "$API/internal/sessions/$2/permission"; }
facade() { # llm-audience token, suffix, body -> HTTP code
  curl -s -o /dev/null -w "%{http_code}" -X POST -H "authorization: Bearer $1" -H 'content-type: application/json' -d "$3" "$API/internal/llm/$2"
}

# ═══ TIER 1 — no-model parity probes ═══════════════════════════════════════
say "TIER 1 — harness registry + facade chat dialect + canonical gate (no model)"

A=$(curl -s -X POST -H "$H" -H 'content-type: application/json' \
  -d '{"name":"qwen-fixer","harness":"qwen-code","policy":"default"}' "$API/v1/agents")
IMG=$(echo "$A" | j "['revision']['runner_image']"); MODEL=$(echo "$A" | j "['revision']['model']")
[ "$MODEL" = "qwen3-coder-plus" ] && ok "qwen agent defaults to qwen3-coder-plus" || no "qwen model default: $MODEL"
echo "$IMG" | grep -q "qwen-runner" && ok "qwen agent defaults to the qwen image" || no "qwen image default: $IMG"
# cross-harness model → 422 (the registry's model_belongs gate)
BAD=$(curl -s -o /dev/null -w "%{http_code}" -X POST -H "$H" -H 'content-type: application/json' \
  -d '{"name":"bogus-qm","harness":"qwen-code","model":"gpt-5.4-mini","policy":"default"}' "$API/v1/agents")
[ "$BAD" = "422" ] && ok "cross-harness model (gpt on qwen) → 422" || no "cross-harness model got $BAD"
# /v1/harnesses lists it (the dashboard's single source of truth)
LISTED=$(curl -s -H "$H" "$API/v1/harnesses" | python3 -c "import sys,json;print(1 if any(h['id']=='qwen-code' for h in json.load(sys.stdin)['harnesses']) else 0)" 2>/dev/null)
[ "$LISTED" = "1" ] && ok "/v1/harnesses lists qwen-code" || no "/v1/harnesses missing qwen-code"

S=$(new_qwen_session true trusted); read -r T TL <<<"$(tok_for "$S")"
[ -n "$T" ] && ok "qwen sandbox launched; got session tokens" || no "no qwen session token"
if [ -n "$T" ]; then
  # canonical verdicts (exactly what the supervisor posts)
  D=$(perm "$T" "$S" '{"tool_call_id":"q1","tool":"Bash","input":{"command":"git status","cwd":"/workspace"}}' | j "['decision']")
  [ "$D" = "allow" ] && ok "canonical Bash{git status} → allow" || no "git status got $D"
  D=$(perm "$T" "$S" '{"tool_call_id":"q2","tool":"Bash","input":{"command":"rm -rf /","cwd":"/workspace"}}' | j "['decision']")
  [ "$D" = "deny" ] && ok "canonical Bash{rm -rf /} → deny" || no "rm got $D"
  D=$(perm "$T" "$S" '{"tool_call_id":"q3","tool":"Read","input":{"file_path":"/workspace/NOTE.txt"}}' | j "['decision']")
  [ "$D" = "allow" ] && ok "canonical Read → allow" || no "Read got $D"
  D=$(perm "$T" "$S" '{"tool_call_id":"q4","tool":"mcp__ws__read","input":{}}' | j "['decision']")
  [ "$D" = "deny" ] && ok "unattached mcp__ws__read → deny (capability)" || no "mcp got $D"
  # digest binding: reuse q1 with DIFFERENT input → hard reject; same input re-attaches
  D=$(perm "$T" "$S" '{"tool_call_id":"q1","tool":"Bash","input":{"command":"curl evil.com","cwd":"/workspace"}}' | j "['decision']")
  [ "$D" = "deny" ] && ok "reused tool_call_id + changed input → deny (digest binding)" || no "digest reuse got $D"
  D=$(perm "$T" "$S" '{"tool_call_id":"q1","tool":"Bash","input":{"command":"git status","cwd":"/workspace"}}' | j "['decision']")
  [ "$D" = "allow" ] && ok "reused tool_call_id + same input → allow (idempotent)" || no "idempotent reuse got $D"

  # facade chat-completions dialect
  CC='{"model":"qwen3-coder-plus","messages":[{"role":"user","content":"hi"}]}'
  C=$(facade "$TL" "v1/chat/completions" '{"model":"gpt-4o","messages":[]}'); [ "$C" = "422" ] && ok "facade qwen: model mismatch → 422" || no "model mismatch got $C"
  C=$(facade "$TL" "v1/responses" "$CC"); [ "$C" = "404" ] && ok "facade qwen: v1/responses suffix → 404 (wrong dialect)" || no "responses suffix got $C"
  C=$(facade "$TL" "v1/messages" "$CC"); [ "$C" = "404" ] && ok "facade qwen: v1/messages suffix → 404 (wrong dialect)" || no "messages suffix got $C"
  C=$(facade "$TL" "v1/chat/completions" '{"model":"qwen3-coder-plus","messages":[],"functions":[{"name":"f"}]}'); [ "$C" = "422" ] && ok "facade qwen: legacy 'functions' → 422" || no "legacy functions got $C"
  C=$(facade "$TL" "v1/chat/completions" '{"model":"qwen3-coder-plus","messages":[],"tools":[{"type":"web_search"}]}'); [ "$C" = "422" ] && ok "facade qwen: non-function tool → 422 (reject, not strip)" || no "non-function tool got $C"
fi

# ReadOnly trust tier (fork PR analog)
S2=$(new_qwen_session true read_only); read -r T2 _ <<<"$(tok_for "$S2")"
if [ -n "$T2" ]; then
  D=$(perm "$T2" "$S2" '{"tool_call_id":"r1","tool":"Bash","input":{"command":"git diff","cwd":"/workspace"}}' | j "['decision']")
  [ "$D" = "allow" ] && ok "ReadOnly: canonical Bash{git diff} → allow" || no "ReadOnly git diff got $D"
  D=$(perm "$T2" "$S2" '{"tool_call_id":"r2","tool":"Write","input":{"file_path":"/workspace/x","content":"y"}}' | j "['decision']")
  [ "$D" = "deny" ] && ok "ReadOnly: canonical Write → deny (trust tier)" || no "ReadOnly Write got $D"
else
  no "no ReadOnly qwen session token — trust-tier probes could not run"
fi

# ═══ TIER 0 — protocol replay: real supervisor, fake qwen CLI, real gate ════
say "TIER 0 — supervisor protocol replay (fake qwen CLI, no model)"
bash "$(dirname "$0")/e2e-qwen-replay.sh" "$SB" && ok "supervisor protocol-replay passed" || no "supervisor protocol-replay FAILED"

# ═══ TIER 2 — live run (self-skips without DASHSCOPE_API_KEY) ═══════════════
say "TIER 2 — live qwen run"
if [ "${E2E_SKIP_LIVE:-0}" = "1" ] || [ -z "${DASHSCOPE_API_KEY:-}" ]; then
  ok "SKIP live tier — E2E_SKIP_LIVE=${E2E_SKIP_LIVE:-0} / DASHSCOPE_API_KEY $([ -n "${DASHSCOPE_API_KEY:-}" ] && echo set || echo unset) (live spend is opt-in by design)"
else
  bash "$(dirname "$0")/e2e-qwen-live.sh" && ok "live qwen run completed + governed" || no "live qwen run FAILED"
fi

say "RESULT"
# Tripwire against silent assertion shrinkage — a FLOOR (>=), sitting below
# the happy no-key count (20) and above any token-miss remnant.
EXPECTED_MIN=18
ran=$((pass + fail))
[ "$ran" -ge "$EXPECTED_MIN" ] && ok "assertion-count tripwire ($ran ran ≥ $EXPECTED_MIN)" \
  || no "only $ran assertions ran (< $EXPECTED_MIN) — silent shrinkage"
printf "  \033[1;32m%d passed\033[0m, \033[1;31m%d failed\033[0m\n" "$pass" "$fail"
exit $(( fail > 0 ? 1 : 0 ))
