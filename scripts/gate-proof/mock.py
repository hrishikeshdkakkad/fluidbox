#!/usr/bin/env python3
"""Mock upstream + mock control plane for scripts/gate-proof.sh.

One process serves two roles the real runner cannot tell apart from the real
things, because it only ever sees them over HTTP:

  * the MODEL upstream  (ANTHROPIC_BASE_URL) — returns a canned `tool_use`, so a
    tool call happens with no model, no key, and no cost; and
  * the CONTROL PLANE   (FLUIDBOX_CONTROL_URL) — answers `/permission` with a
    verdict this harness chooses per scenario, and records every call.

Everything is stdlib. Every request is appended to a JSONL so the assertions are
made against what the runner ACTUALLY did, not against what it was supposed to.

Scenario knobs (env):
  GP_MODE        allow | deny | http500 | unauth401 | wrongaud403 | nonjson | emptyjson
  GP_COMMAND     the Bash command the canned tool_use asks for
  GP_HOLD_SECS   seconds to hold the /permission response before answering
  GP_PORT        listen port
  GP_LOG         path to the JSONL request log
"""

import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MODE = os.environ.get("GP_MODE", "deny")
COMMAND = os.environ.get("GP_COMMAND", "echo hello")
HOLD = float(os.environ.get("GP_HOLD_SECS", "0"))
PORT = int(os.environ.get("GP_PORT", "8799"))
LOG = os.environ.get("GP_LOG", "/tmp/gate-proof.jsonl")
TOOL_CALL_ID = os.environ.get("GP_TOOL_CALL_ID", "toolu_gateproof_0001")

_lock = threading.Lock()
_turns = {"messages": 0}


def record(entry):
    entry["t_ms"] = int(time.time() * 1000)
    with _lock:
        with open(LOG, "a") as f:
            f.write(json.dumps(entry) + "\n")
            f.flush()


def sse(blocks):
    """Serialize an Anthropic streaming response."""
    out = []

    def ev(name, payload):
        out.append(f"event: {name}\ndata: {json.dumps(payload)}\n\n")

    ev(
        "message_start",
        {
            "type": "message_start",
            "message": {
                "id": "msg_gateproof",
                "type": "message",
                "role": "assistant",
                "model": "claude-haiku-4-5",
                "content": [],
                "stop_reason": None,
                "stop_sequence": None,
                "usage": {"input_tokens": 8, "output_tokens": 1},
            },
        },
    )
    stop_reason = "end_turn"
    for i, b in enumerate(blocks):
        if b["type"] == "tool_use":
            stop_reason = "tool_use"
            ev(
                "content_block_start",
                {
                    "type": "content_block_start",
                    "index": i,
                    "content_block": {
                        "type": "tool_use",
                        "id": b["id"],
                        "name": b["name"],
                        "input": {},
                    },
                },
            )
            ev(
                "content_block_delta",
                {
                    "type": "content_block_delta",
                    "index": i,
                    "delta": {
                        "type": "input_json_delta",
                        "partial_json": json.dumps(b["input"]),
                    },
                },
            )
        else:
            ev(
                "content_block_start",
                {
                    "type": "content_block_start",
                    "index": i,
                    "content_block": {"type": "text", "text": ""},
                },
            )
            ev(
                "content_block_delta",
                {
                    "type": "content_block_delta",
                    "index": i,
                    "delta": {"type": "text_delta", "text": b["text"]},
                },
            )
        ev("content_block_stop", {"type": "content_block_stop", "index": i})
    ev(
        "message_delta",
        {
            "type": "message_delta",
            "delta": {"stop_reason": stop_reason, "stop_sequence": None},
            "usage": {"output_tokens": 12},
        },
    )
    ev("message_stop", {"type": "message_stop"})
    return "".join(out).encode()


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):  # silence the default stderr spam
        pass

    def _send(self, code, body=b"", ctype="application/json"):
        self.send_response(code)
        self.send_header("content-type", ctype)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        record({"kind": "get", "path": self.path})
        self._send(200, b"{}")

    def do_POST(self):
        n = int(self.headers.get("content-length") or 0)
        raw = self.rfile.read(n) if n else b""
        # STRIP THE QUERY STRING. The pinned CLI posts to `/v1/messages?beta=true`,
        # so an endswith("/v1/messages") match silently misses every model call —
        # the CLI then reports "There's an issue with the selected model", which
        # looks like a model problem and is actually a routing bug in this mock.
        path = self.path.split("?", 1)[0]

        # ── the model upstream ────────────────────────────────────────────
        if path.endswith("/v1/messages/count_tokens"):
            self._send(200, json.dumps({"input_tokens": 8}).encode())
            return
        if path.endswith("/v1/messages"):
            body_text = raw.decode("utf-8", "replace")
            # The CLI makes UTILITY calls on this same route (conversation-title
            # generation, and similar). They carry no tool definitions. Counting
            # them as agentic turns would hand the canned tool_use to the title
            # generator and never to the agent loop, so they get a plain text
            # answer and do not advance the turn counter.
            is_agentic = '"name":"Bash"' in body_text or '"name": "Bash"' in body_text
            if not is_agentic:
                record({"kind": "messages_utility", "bytes": len(body_text)})
                payload = sse([{"type": "text", "text": "ok"}])
                self.send_response(200)
                self.send_header("content-type", "text/event-stream")
                self.send_header("cache-control", "no-cache")
                self.send_header("content-length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            with _lock:
                _turns["messages"] += 1
                turn = _turns["messages"]
            record(
                {
                    "kind": "messages",
                    "turn": turn,
                    # The whole body: turn 2 carries the tool_result, which is
                    # where an EXECUTED read-only command's output shows up.
                    # This is the unfabricatable witness for commands that leave
                    # no filesystem trace.
                    "body": body_text,
                }
            )
            if turn == 1:
                blocks = [
                    {
                        "type": "tool_use",
                        "id": TOOL_CALL_ID,
                        "name": "Bash",
                        "input": {"command": COMMAND, "description": "gate proof probe"},
                    }
                ]
            else:
                blocks = [{"type": "text", "text": "gate-proof turn %d done" % turn}]
            self.send_response(200)
            self.send_header("content-type", "text/event-stream")
            self.send_header("cache-control", "no-cache")
            payload = sse(blocks)
            self.send_header("content-length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return

        # ── the control plane ─────────────────────────────────────────────
        if path.endswith("/permission"):
            try:
                body = json.loads(raw or b"{}")
            except Exception:
                body = {}
            record(
                {
                    "kind": "permission",
                    "tool": body.get("tool"),
                    "tool_call_id": body.get("tool_call_id"),
                    "input": body.get("input"),
                    "mode": MODE,
                }
            )
            if HOLD > 0:
                # Hold the verdict OPEN. Nothing may execute during this window;
                # the side effect's timestamp versus `answered_at` below is the
                # ordering proof.
                time.sleep(HOLD)
            if MODE == "http500":
                self._send(500, b'{"error":"boom"}')
            elif MODE == "unauth401":
                self._send(401, b'{"error":"unauthorized"}')
            elif MODE == "wrongaud403":
                self._send(403, b'{"error":"wrong_audience"}')
            elif MODE == "nonjson":
                self._send(200, b"this is not json at all", "text/plain")
            elif MODE == "emptyjson":
                self._send(200, b"{}")
            elif MODE == "allow":
                self._send(200, json.dumps({"decision": "allow"}).encode())
            else:
                self._send(
                    200,
                    json.dumps(
                        {"decision": "deny", "message": "denied by the gate proof"}
                    ).encode(),
                )
            record({"kind": "permission_answered", "mode": MODE})
            return

        if path.endswith("/events"):
            try:
                body = json.loads(raw or b"{}")
            except Exception:
                body = {}
            record({"kind": "event", "body": body})
            self._send(200, b"{}")
            return
        if path.endswith("/heartbeat"):
            self._send(200, b"{}")
            return
        if path.endswith("/result"):
            try:
                body = json.loads(raw or b"{}")
            except Exception:
                body = {}
            record({"kind": "result", "body": body})
            self._send(200, b"{}")
            return
        if path.endswith("/token/renew"):
            self._send(200, json.dumps({"renewed": True}).encode())
            return

        record({"kind": "unhandled", "path": path, "body": raw.decode("utf-8", "replace")[:400]})
        self._send(404, b'{"error":"not found"}')


if __name__ == "__main__":
    open(LOG, "w").close()
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), H)
    srv.daemon_threads = True
    print("gate-proof mock listening on %d (mode=%s)" % (PORT, MODE), flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    sys.exit(0)
