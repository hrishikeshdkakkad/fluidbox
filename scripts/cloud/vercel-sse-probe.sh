#!/usr/bin/env bash
# M1.0 gate proof — "Probe Vercel proxy behavior for the Core cookie and
# long-lived server-sent events" + "Document the fallback if Vercel cannot
# reliably carry long-lived streams".
#
# Splits the question into the two things that are actually separate:
#
#   CODE PATH (provable anywhere, incl. locally):
#     S1  the dashboard proxy streams SSE UNBUFFERED (first byte arrives at the
#         origin's cadence, not at stream end)
#     S2  the stream survives a long quiet-ish period with keepalives
#     S3  Last-Event-ID is forwarded upstream, so a capped stream RESUMES
#     C1  a __Host- session cookie set by core survives the proxy hop
#     C2  a login-leg redirect Location survives with its cookie
#
#   PLATFORM CAP (only measurable on the real deployment):
#     the function duration ceiling that ends an otherwise-healthy stream.
#
# One script, two targets:
#   scripts/cloud/vercel-sse-probe.sh                       # local `next start`
#   TARGET=https://<preview>.vercel.app scripts/cloud/vercel-sse-probe.sh
#
# The origin is a deterministic local SSE/cookie server (no core, no DB, no
# model calls) so the measurement isolates the PROXY. When TARGET is a Vercel
# deployment it must be built with FLUIDBOX_API_URL pointing at a tunnel to
# this probe origin (ngrok/cloudflared) — the script prints the exact recipe.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.." || exit 1
. scripts/cloud/lib.sh

ORIGIN_PORT="${ORIGIN_PORT:-8795}"
WEB_PORT="${WEB_PORT:-3010}"
DURATION="${DURATION:-120}"        # seconds to hold the stream open
KEEPALIVE="${KEEPALIVE:-15}"       # origin keepalive cadence (core's is 15s)
TARGET="${TARGET:-}"               # empty ⇒ start a local `next start`
WORK="${SCRATCH:-/tmp/fluidbox-sse-probe}"
EV=$(evidence_dir cloud-m1-readiness)
mkdir -p "$WORK"

PASS=0; FAILN=0
pass() { ok "$1"; PASS=$((PASS+1)); }
bad()  { fail "$1"; FAILN=$((FAILN+1)); }
cleanup() {
  for f in origin.pid web.pid; do
    [ -f "$WORK/$f" ] && kill "$(cat "$WORK/$f")" 2>/dev/null
  done
  return 0
}
trap cleanup EXIT

# ── the deterministic origin ────────────────────────────────────────────────
cat > "$WORK/origin.mjs" <<'JS'
import { createServer } from "node:http";
const PORT = Number(process.env.PORT || 8795);
const KEEPALIVE = Number(process.env.KEEPALIVE || 15) * 1000;

createServer((req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);
  // SSE: emits an immediate first event, then keepalive comments, forever.
  if (url.pathname.endsWith("/events/stream")) {
    const lastId = Number(req.headers["last-event-id"] || 0);
    res.writeHead(200, {
      "content-type": "text/event-stream",
      "cache-control": "no-cache, no-transform",
      connection: "keep-alive",
      // Echo what we received so the proxy hop can be verified from the client.
      "x-probe-last-event-id": String(lastId),
    });
    let seq = lastId;
    res.write(`id: ${++seq}\nevent: probe.open\ndata: {"t":${Date.now()},"resumed_from":${lastId}}\n\n`);
    const t = setInterval(() => {
      res.write(`id: ${++seq}\nevent: probe.tick\ndata: {"t":${Date.now()},"seq":${seq}}\n\n`);
    }, KEEPALIVE);
    req.on("close", () => clearInterval(t));
    return;
  }
  // Login-leg shape: a redirect that also sets the core session cookie.
  if (url.pathname.endsWith("/auth/callback")) {
    res.writeHead(303, {
      location: "/app",
      "set-cookie": [
        "__Host-fbx_web=probe-session-value; Path=/; Secure; HttpOnly; SameSite=Lax",
        "__Host-fbx_login_probe=; Path=/; Secure; HttpOnly; Max-Age=0",
      ],
      "content-type": "text/plain",
    });
    res.end("redirecting");
    return;
  }
  res.writeHead(200, { "content-type": "application/json" });
  res.end(JSON.stringify({ ok: true, path: url.pathname }));
}).listen(PORT, "127.0.0.1", () => console.log(`probe origin on ${PORT}`));
JS

say "probe origin (deterministic SSE + cookie server)"
PORT="$ORIGIN_PORT" KEEPALIVE="$KEEPALIVE" node "$WORK/origin.mjs" > "$WORK/origin.log" 2>&1 &
echo $! > "$WORK/origin.pid"
sleep 1
curl -fsS --max-time 5 "http://127.0.0.1:$ORIGIN_PORT/health" >/dev/null \
  && pass "origin up on :$ORIGIN_PORT (keepalive ${KEEPALIVE}s)" \
  || die "probe origin failed to start" "$WORK/origin.log"

# ── the target under test ───────────────────────────────────────────────────
if [ -z "$TARGET" ]; then
  say "building + starting apps/web locally in SSO MODE (the deployed configuration)"
  ( cd apps/web && \
    FLUIDBOX_WEB_MODE=sso \
    FLUIDBOX_API_URL="http://127.0.0.1:$ORIGIN_PORT" \
    FLUIDBOX_PUBLIC_URL="http://127.0.0.1:$WEB_PORT" \
    ./node_modules/.bin/next build ) > "$WORK/build.log" 2>&1 \
    || die "next build failed" "$WORK/build.log"
  pass "next build (sso mode; FLUIDBOX_API_URL baked into the /v1 rewrite AT BUILD TIME — the documented trap)"
  ( cd apps/web && \
    FLUIDBOX_WEB_MODE=sso \
    FLUIDBOX_API_URL="http://127.0.0.1:$ORIGIN_PORT" \
    FLUIDBOX_PUBLIC_URL="http://127.0.0.1:$WEB_PORT" \
    PORT="$WEB_PORT" ./node_modules/.bin/next start -p "$WEB_PORT" ) > "$WORK/web.log" 2>&1 &
  echo $! > "$WORK/web.pid"
  for _ in $(seq 1 60); do curl -fsS --max-time 2 "http://127.0.0.1:$WEB_PORT/login" >/dev/null 2>&1 && break; sleep 1; done
  TARGET="http://127.0.0.1:$WEB_PORT"
  curl -fsS --max-time 5 "$TARGET/login" >/dev/null 2>&1 || die "next start never became ready" "$WORK/web.log"
  pass "dashboard serving on $TARGET"
  MODE_LABEL="LOCAL next start (code path only — platform cap NOT measured)"
else
  MODE_LABEL="DEPLOYED $TARGET (code path + platform cap)"
  ok "probing deployed target: $TARGET"
fi

# ── S1/S2: unbuffered, long-lived SSE through the proxy ─────────────────────
say "S1/S2 SSE through the dashboard proxy for ${DURATION}s"
SSE_OUT="$WORK/sse.txt"
: > "$SSE_OUT"
START=$(date +%s)
curl -sN --max-time "$((DURATION + 15))" \
  -H 'accept: text/event-stream' \
  "$TARGET/api/fluidbox/sessions/probe/events/stream" \
  > "$SSE_OUT" 2>"$WORK/sse.err" &
SSE_PID=$!
FIRST_BYTE_AT=""
for _ in $(seq 1 40); do
  [ -s "$SSE_OUT" ] && { FIRST_BYTE_AT=$(( $(date +%s) - START )); break; }
  sleep 0.25
done
if [ -n "$FIRST_BYTE_AT" ] && [ "$FIRST_BYTE_AT" -le 5 ]; then
  pass "first byte after ${FIRST_BYTE_AT}s — proxy streams UNBUFFERED"
else
  bad "no first byte within 10s — the proxy is buffering (or the route errored); see $WORK/sse.err"
fi
sleep "$DURATION"
kill "$SSE_PID" 2>/dev/null
ELAPSED=$(( $(date +%s) - START ))
TICKS=$(grep -c '^event: probe.tick' "$SSE_OUT" 2>/dev/null || echo 0)
EXPECT=$(( DURATION / KEEPALIVE ))
cp "$SSE_OUT" "$EV/sse-stream-sample.txt" 2>/dev/null || true
echo "  held ${ELAPSED}s, received $TICKS keepalive ticks (expected ~$EXPECT)"
if [ "$TICKS" -ge $(( EXPECT > 1 ? EXPECT - 1 : 1 )) ]; then
  pass "stream survived ${DURATION}s with continuous delivery"
else
  bad "stream delivered only $TICKS/$EXPECT ticks — it was cut short (THIS is the cap; record the elapsed time)"
fi

# ── S3: Last-Event-ID forwarding (the resume contract) ──────────────────────
say "S3 Last-Event-ID forwarding (what makes a capped stream resumable)"
RESUME=$(curl -sN --max-time 8 -H 'accept: text/event-stream' -H 'last-event-id: 42' \
  "$TARGET/api/fluidbox/sessions/probe/events/stream" 2>/dev/null | head -3)
printf '%s\n' "$RESUME" > "$EV/sse-resume-sample.txt"
case "$RESUME" in
  *'"resumed_from":42'*) pass "Last-Event-ID reached the origin — resume works through the proxy";;
  *) bad "origin did not see Last-Event-ID=42 (resume would restart from 0): $RESUME";;
esac

# ── C1/C2: core session cookie + redirect survive the proxy ────────────────
say "C1/C2 core cookie + login-leg redirect through the proxy"
curl -s -D "$WORK/cookie-headers.txt" -o /dev/null --max-time 15 \
  "$TARGET/api/fluidbox/auth/callback"
cp "$WORK/cookie-headers.txt" "$EV/cookie-proxy-headers.txt" 2>/dev/null || true
grep -qi 'set-cookie: *__Host-fbx_web=' "$WORK/cookie-headers.txt" \
  && pass "__Host-fbx_web survived the proxy hop (lands on the dashboard origin)" \
  || bad "__Host-fbx_web did NOT survive the proxy — login could never complete"
grep -qi 'set-cookie: *__Host-fbx_login_probe=' "$WORK/cookie-headers.txt" \
  && pass "the login-flow cookie clear survived too (all Set-Cookie headers kept distinct)" \
  || warn "second Set-Cookie not seen (getSetCookie should keep them distinct)"
grep -qi '^location: */app' "$WORK/cookie-headers.txt" \
  && pass "redirect Location propagated" \
  || bad "redirect Location dropped — the login dance would stall"

say "verdict — $MODE_LABEL"
echo "  PASS=$PASS FAIL=$FAILN   evidence: $EV/"
if [ -z "${TARGET##http://127.0.0.1*}" ]; then
  cat <<EOT

  PLATFORM CAP NOT MEASURED (this was the local code-path run). To finish the
  M1.0 proof once the Vercel project is linked (M1 brief §12 decision):

    ngrok http $ORIGIN_PORT                      # public URL for the probe origin
    cd apps/web && vercel link                   # the reserved user decision
    vercel env add FLUIDBOX_WEB_MODE preview     # value: sso
    vercel env add FLUIDBOX_API_URL preview      # value: the ngrok https URL
    vercel deploy                                # build-time rewrite bakes the URL
    DURATION=900 TARGET=https://<preview>.vercel.app scripts/cloud/vercel-sse-probe.sh

  A stream that ends early is the FUNCTION DURATION CAP: record the elapsed
  seconds — that number is the reconnect cadence the dashboard will show, and
  it feeds the fallback decision in docs/hosted/cloud-architecture.md.
EOT
fi
[ "$FAILN" -eq 0 ] || exit 1
