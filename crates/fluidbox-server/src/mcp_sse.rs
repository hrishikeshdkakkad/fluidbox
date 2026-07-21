//! Incremental SSE (`text/event-stream`) event assembler for the MCP
//! Streamable-HTTP broker (Phase E, E6).
//!
//! Replaces the old whole-body `data:`-line scanner (survey A §1g): a real
//! WHATWG-shaped parser that assembles multi-line `data:` fields (joined with
//! `\n`), honors `event:`/`id:`/`retry:` framing and comment lines, dispatches
//! on a blank line, and tolerates CRLF/LF/CR terminators. Each event is bounded
//! to [`MAX_EVENT_BYTES`]; an oversize event is an ERROR (never silent
//! truncation), surfaced up so the broker aborts the call as a protocol violation.
//!
//! **How the broker actually dials it (survey A §1g):** the transport funnel
//! (`broker::dial_rpc`) buffers the WHOLE decoded response body — bounded to 8
//! MiB by the streaming read — and then feeds it to the assembler in ONE
//! [`feed`](SseEventAssembler::feed) + [`finish`](SseEventAssembler::finish)
//! call; the per-event 256 KiB cap is enforced DURING that single feed. The
//! assembler itself is nonetheless a true INCREMENTAL parser — [`feed`] carries a
//! partial line across chunk boundaries and returns only the events completed so
//! far — and its tests exercise byte-split and CRLF-split chunks, so a future
//! streaming dial path can feed it chunk-by-chunk without any change here. This
//! module contributes the per-event bound the old scanner lacked; the whole-body
//! 8 MiB bound stays the broker's.
//!
//! Named `mcp_sse` (not `sse`) to stay clearly distinct from the crate's
//! OUTBOUND server-sent-events module (`sse.rs`, the run event stream).

/// Per-event payload ceiling (accumulated `data:` bytes). An event exceeding it
/// is refused as a protocol error — a single event can never balloon memory or
/// the runner context past this, independent of the whole-body 8 MiB cap.
pub const MAX_EVENT_BYTES: usize = 256 * 1024;

/// One dispatched SSE event. `data` is the `data:` lines joined by `\n`
/// (the WHATWG rule); `event`/`id`/`retry` are the optional framing fields.
#[derive(Debug, Clone, PartialEq)]
pub struct SseEvent {
    pub event: Option<String>,
    pub data: String,
    pub id: Option<String>,
    pub retry: Option<u64>,
}

/// Incremental event assembler. Feed decoded response bytes as they arrive (or
/// the whole body at once); each [`feed`](Self::feed) returns the events that
/// completed within that chunk, and [`finish`](Self::finish) flushes a trailing
/// event that lacked its final blank line (lenient — real MCP servers usually
/// terminate with `\n\n`, but some do not).
#[derive(Default)]
pub struct SseEventAssembler {
    /// Bytes not yet forming a complete line (carried across chunk boundaries,
    /// incl. a lone trailing `\r` that might still be part of a `\r\n`).
    line_buf: Vec<u8>,
    // The event under construction.
    cur_event: Option<String>,
    cur_data: Vec<String>,
    cur_id: Option<String>,
    cur_retry: Option<u64>,
    /// Accumulated `data:` bytes for the current event (the cap unit).
    cur_data_bytes: usize,
}

impl SseEventAssembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed a decoded chunk; returns every event that completed. `Err` on a
    /// single event exceeding [`MAX_EVENT_BYTES`] (the caller aborts the call).
    pub fn feed(&mut self, chunk: &[u8]) -> Result<Vec<SseEvent>, String> {
        self.line_buf.extend_from_slice(chunk);
        let mut out = Vec::new();
        // Extract every COMPLETE line; hold an incomplete tail (and a lone
        // trailing `\r`, which might still be the first half of a `\r\n`).
        while let Some(term) = self.line_buf.iter().position(|&b| b == b'\n' || b == b'\r') {
            let consume_to = if self.line_buf[term] == b'\r' {
                if term + 1 == self.line_buf.len() {
                    // A `\r` at the very end: wait for the next byte to know
                    // whether it is a bare CR or the CR of a CRLF.
                    break;
                }
                if self.line_buf[term + 1] == b'\n' {
                    term + 2
                } else {
                    term + 1
                }
            } else {
                term + 1
            };
            let line: Vec<u8> = self.line_buf.drain(..consume_to).collect();
            let line = &line[..term]; // strip the terminator byte(s)
            if let Some(ev) = self.process_line(line)? {
                out.push(ev);
            }
        }
        Ok(out)
    }

    /// Flush a trailing event that never got its blank-line terminator (and any
    /// final unterminated line still buffered). Idempotent once drained.
    pub fn finish(&mut self) -> Vec<SseEvent> {
        let mut out = Vec::new();
        // A final line with no terminator (incl. a held lone `\r`).
        if !self.line_buf.is_empty() {
            let line: Vec<u8> = std::mem::take(&mut self.line_buf);
            // A held-back lone trailing `\r` is a line terminator, not content.
            let line = if line.last() == Some(&b'\r') {
                &line[..line.len() - 1]
            } else {
                &line[..]
            };
            // process_line only errors on data overflow; at finish we prefer a
            // best-effort flush, so swallow that (the body cap already bounds it).
            // A blank final line dispatches HERE — capture it, don't drop it.
            if let Ok(Some(ev)) = self.process_line(line) {
                out.push(ev);
            }
        }
        // A non-blank final line leaves an unterminated event to flush.
        if let Some(ev) = self.dispatch() {
            out.push(ev);
        }
        out
    }

    /// Process one terminator-stripped line. Returns a dispatched event when the
    /// line was blank (end of an event with data).
    fn process_line(&mut self, line: &[u8]) -> Result<Option<SseEvent>, String> {
        if line.is_empty() {
            return Ok(self.dispatch());
        }
        // A leading ':' is a comment line — ignored (keep-alive/heartbeat).
        if line[0] == b':' {
            return Ok(None);
        }
        let text = String::from_utf8_lossy(line);
        // `field:value`; a line with no ':' is `field` with an empty value.
        let (field, value) = match text.find(':') {
            Some(i) => {
                let v = &text[i + 1..];
                // Strip exactly ONE leading space from the value (WHATWG).
                (&text[..i], v.strip_prefix(' ').unwrap_or(v))
            }
            None => (&text[..], ""),
        };
        match field {
            "event" => self.cur_event = Some(value.to_string()),
            "data" => {
                // +1 for the '\n' that will join this line (WHATWG appends a
                // newline per data line); count it toward the per-event cap.
                self.cur_data_bytes += value.len() + 1;
                if self.cur_data_bytes > MAX_EVENT_BYTES {
                    return Err(format!(
                        "mcp SSE event exceeds the {MAX_EVENT_BYTES}-byte per-event cap"
                    ));
                }
                self.cur_data.push(value.to_string());
            }
            // Per WHATWG, an id containing a NUL is ignored.
            "id" if !value.contains('\u{0}') => self.cur_id = Some(value.to_string()),
            "retry" => {
                if let Ok(n) = value.parse::<u64>() {
                    self.cur_retry = Some(n);
                }
            }
            _ => {} // unknown field: ignore (spec-compliant forward-compat)
        }
        Ok(None)
    }

    /// Dispatch the current event on a blank line: only when it carries data
    /// (WHATWG: an empty data buffer dispatches nothing). Resets the builder.
    fn dispatch(&mut self) -> Option<SseEvent> {
        if self.cur_data.is_empty() {
            // No data → nothing to dispatch; still reset any stray framing so a
            // comment-only or field-only block doesn't bleed into the next event.
            self.cur_event = None;
            self.cur_id = None;
            self.cur_retry = None;
            self.cur_data_bytes = 0;
            return None;
        }
        let ev = SseEvent {
            event: self.cur_event.take(),
            data: std::mem::take(&mut self.cur_data).join("\n"),
            id: self.cur_id.take(),
            retry: self.cur_retry.take(),
        };
        self.cur_data_bytes = 0;
        Some(ev)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed_all(input: &str) -> Vec<SseEvent> {
        let mut a = SseEventAssembler::new();
        let mut out = a.feed(input.as_bytes()).expect("no overflow");
        out.extend(a.finish());
        out
    }

    #[test]
    fn single_event_data_and_framing() {
        let evs = feed_all("event: message\nid: 7\nretry: 2500\ndata: {\"x\":1}\n\n");
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].event.as_deref(), Some("message"));
        assert_eq!(evs[0].id.as_deref(), Some("7"));
        assert_eq!(evs[0].retry, Some(2500));
        assert_eq!(evs[0].data, "{\"x\":1}");
    }

    #[test]
    fn multi_line_data_is_joined_with_newlines() {
        let evs = feed_all("data: line1\ndata: line2\ndata: line3\n\n");
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].data, "line1\nline2\nline3");
    }

    #[test]
    fn crlf_terminators_parse_identically_to_lf() {
        let evs = feed_all("event: message\r\ndata: {\"ok\":true}\r\n\r\n");
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].event.as_deref(), Some("message"));
        assert_eq!(evs[0].data, "{\"ok\":true}");
    }

    #[test]
    fn bare_cr_terminators_parse() {
        // Old Mac-style lone CR line endings.
        let evs = feed_all("data: a\rdata: b\r\r");
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].data, "a\nb");
    }

    #[test]
    fn comment_lines_are_ignored() {
        let evs = feed_all(": keep-alive\ndata: y\n: another comment\n\n");
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].data, "y");
    }

    #[test]
    fn interleaved_events_split_on_blank_lines() {
        let evs = feed_all(
            "data: {\"id\":1,\"result\":{}}\n\ndata: {\"id\":2,\"result\":{}}\n\ndata: {\"id\":3}\n\n",
        );
        assert_eq!(evs.len(), 3);
        assert_eq!(evs[0].data, "{\"id\":1,\"result\":{}}");
        assert_eq!(evs[1].data, "{\"id\":2,\"result\":{}}");
        assert_eq!(evs[2].data, "{\"id\":3}");
    }

    #[test]
    fn field_or_comment_only_block_dispatches_nothing() {
        // An event carrying only framing (no data) is not dispatched.
        let evs = feed_all("event: ping\n\ndata: real\n\n");
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].data, "real");
        assert!(
            evs[0].event.is_none(),
            "stale event type must not bleed over"
        );
    }

    #[test]
    fn split_across_chunks_reassembles() {
        let mut a = SseEventAssembler::new();
        // A single JSON payload split mid-value across three feeds, plus the
        // blank-line terminator arriving separately.
        assert!(a.feed(b"data: {\"jsonrpc\":\"2.0\",").unwrap().is_empty());
        assert!(a.feed(b"\ndata: \"id\":9}").unwrap().is_empty());
        let evs = a.feed(b"\n\n").unwrap();
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].data, "{\"jsonrpc\":\"2.0\",\n\"id\":9}");
    }

    #[test]
    fn crlf_split_across_chunk_boundary() {
        // The CR ends one chunk; the LF starts the next — must be ONE terminator,
        // not a bare-CR line followed by a blank LF line.
        let mut a = SseEventAssembler::new();
        assert!(a.feed(b"data: split\r").unwrap().is_empty());
        let evs = a.feed(b"\n\r\n").unwrap();
        assert_eq!(evs.len(), 1, "CR+LF across the boundary is one line break");
        assert_eq!(evs[0].data, "split");
    }

    #[test]
    fn oversize_event_is_an_error_not_truncation() {
        let mut a = SseEventAssembler::new();
        let huge = format!("data: {}\n", "x".repeat(MAX_EVENT_BYTES + 10));
        let err = a
            .feed(huge.as_bytes())
            .expect_err("must reject oversize event");
        assert!(err.contains("per-event cap"), "got: {err}");
        // FALSE-GREEN guard: a payload JUST under the cap does NOT error.
        let mut b = SseEventAssembler::new();
        let ok = format!("data: {}\n\n", "x".repeat(MAX_EVENT_BYTES - 100));
        assert!(b.feed(ok.as_bytes()).is_ok(), "under-cap event must pass");
    }

    #[test]
    fn finish_flushes_an_unterminated_trailing_event() {
        // No trailing blank line — finish must still surface the event.
        let mut a = SseEventAssembler::new();
        assert!(a
            .feed(b"data: {\"id\":1,\"result\":{}}")
            .unwrap()
            .is_empty());
        let evs = a.finish();
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].data, "{\"id\":1,\"result\":{}}");
    }
}
