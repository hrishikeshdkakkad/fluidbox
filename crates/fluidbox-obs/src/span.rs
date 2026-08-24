//! Correlation spans — the machinery that makes one line joinable to another.
//!
//! # The problem
//!
//! A log line that says `transition failed: pool timed out` is nearly useless.
//! The same line carrying `session_id`, `tenant_id` and `request_id` answers
//! *whose* run broke, *which* caller asked for it, and whether the other 40
//! lines around it belong to the same story. Adding those ids by hand at every
//! callsite is what nobody does after the first week, which is why they have to
//! be inherited rather than typed.
//!
//! `tracing` spans do exactly that: fields recorded on a span are attached to
//! every record emitted inside it, at any depth, across `.await` points, without
//! the callsite knowing. This module is the small set of span shapes this system
//! uses, so the ids are spelled the same way everywhere and the levels are right.
//!
//! # Why these spans are created at INFO (and why `init` pins them enabled)
//!
//! A span only attaches its fields if the span itself passed the filter. The
//! pre-existing `debug_span!("http", …)` in `main.rs` therefore contributed
//! *nothing* at the default `info` filter — the span was disabled, so no record
//! ever carried it. Correlation that silently evaporates at the default log
//! level is worse than none, because it looks like it is working.
//!
//! Two things fix it. These spans are created at INFO, and
//! [`crate::init`] always appends a `fluidbox_obs=trace` directive to the
//! filter. Every span here is constructed *inside this crate*, so that one
//! directive keeps correlation alive even under `RUST_LOG=warn`, where the
//! ERROR records that most need context are the only ones left.
//!
//! # Trace identity
//!
//! `request_id` is a UUIDv7 — time-ordered, so a log store sorts records by it
//! naturally. The W3C `trace_id` is that same value rendered as 32 lowercase hex
//! characters, so there is one identifier in two encodings rather than two
//! identifiers to reconcile. When a caller supplies a `traceparent` header its
//! trace id is adopted instead, which is what lets these records join a trace
//! that started upstream.

use tracing::Span;
use uuid::Uuid;

/// Span name for an inbound HTTP request.
pub const HTTP: &str = "http";
/// Span name for one run's lifecycle work.
pub const RUN: &str = "run";
/// Span name for a background worker tick.
pub const WORKER: &str = "worker";
/// Span name for one outbound call to a third party.
pub const UPSTREAM: &str = "upstream";
/// Span name for one permission-gate decision.
pub const GATE: &str = "gate";

/// A fresh request id. UUIDv7 so ordering by id is ordering by time.
pub fn new_request_id() -> Uuid {
    Uuid::now_v7()
}

/// Render a request id as a W3C trace id: 32 lowercase hex characters.
pub fn trace_id_of(request_id: &Uuid) -> String {
    request_id.simple().to_string()
}

/// Extract the trace id from a W3C `traceparent` header value.
///
/// Format: `00-<32 hex trace-id>-<16 hex parent-id>-<2 hex flags>`. Returns
/// `None` for anything malformed or for the all-zero trace id, which the spec
/// defines as invalid — adopting it would merge unrelated requests into one
/// "trace" and is a favourite way for a broken client to poison a trace store.
///
/// The value is attacker-controlled (any client can send a header), so it is
/// validated for shape and length rather than trusted; a rejected header just
/// means the request starts its own trace.
pub fn trace_id_from_traceparent(header: &str) -> Option<String> {
    let mut parts = header.trim().split('-');
    let version = parts.next()?;
    let trace_id = parts.next()?;
    // Version `ff` is forbidden by the spec; anything else is forward-compatible
    // as long as the trace-id field is where we expect it.
    if version.len() != 2 || version.eq_ignore_ascii_case("ff") {
        return None;
    }
    if trace_id.len() != 32 || !trace_id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    if trace_id.bytes().all(|b| b == b'0') {
        return None;
    }
    Some(trace_id.to_ascii_lowercase())
}

/// The span every record produced while serving one HTTP request lives inside.
///
/// `route` is the ROUTE PATTERN (`/v1/sessions/{id}`), never the concrete path,
/// so "which endpoint is slow" is a group-by rather than a regex. The concrete
/// id is on the record as `session_id`, which is more useful anyway. `path` is
/// carried separately and is already query-stripped by the caller — query
/// strings hold OAuth codes and GitHub flow tokens.
pub fn request(
    plane: &'static str,
    method: &str,
    route: &str,
    request_id: &str,
    trace_id: &str,
) -> Span {
    tracing::info_span!(
        HTTP,
        plane = plane,
        method = method,
        route = route,
        request_id = request_id,
        trace_id = trace_id,
    )
}

/// The span for work belonging to one run. Opened by the orchestrator, the
/// workers, and the internal-plane handlers so that every record about a run —
/// from any plane, on any task — carries its ids.
pub fn run(session_id: &str, tenant_id: &str) -> Span {
    tracing::info_span!(RUN, session_id = session_id, tenant_id = tenant_id)
}

/// The span for one background worker tick, so a sweeper's records are
/// attributable to the sweeper rather than to whatever ran before it.
pub fn worker(name: &'static str) -> Span {
    tracing::info_span!(WORKER, worker = name)
}

/// The span for one outbound call to a third party. `host` only — never the URL,
/// which carries query material.
pub fn upstream(kind: &'static str, host: &str) -> Span {
    tracing::info_span!(UPSTREAM, upstream_kind = kind, host = host)
}

/// The span for one permission-gate decision.
pub fn gate(tool: &str, tool_call_id: &str) -> Span {
    tracing::info_span!(GATE, tool = tool, tool_call_id = tool_call_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field;

    #[test]
    fn trace_id_is_the_request_id_in_w3c_shape() {
        let id = new_request_id();
        let t = trace_id_of(&id);
        assert_eq!(t.len(), 32);
        assert!(t
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
        // Same identifier, two encodings — a reader can go back and forth.
        assert_eq!(t, id.to_string().replace('-', ""));
    }

    #[test]
    fn valid_traceparent_is_adopted() {
        let h = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        assert_eq!(
            trace_id_from_traceparent(h).as_deref(),
            Some("4bf92f3577b34da6a3ce929d0e0e4736")
        );
        // Case is normalised so two spellings of one trace do not become two.
        assert_eq!(
            trace_id_from_traceparent("00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01")
                .as_deref(),
            Some("4bf92f3577b34da6a3ce929d0e0e4736")
        );
    }

    /// The header is attacker-controlled. Every malformed shape must fall back
    /// to a fresh trace rather than propagating junk into the trace store.
    #[test]
    fn malformed_or_forbidden_traceparent_is_rejected() {
        for bad in [
            "",
            "garbage",
            "00",
            "00-tooshort-00f067aa0ba902b7-01",
            // All-zero trace id: explicitly invalid per the spec, and a great
            // way to collapse every request into one "trace".
            "00-00000000000000000000000000000000-00f067aa0ba902b7-01",
            // Version ff is forbidden.
            "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            // Non-hex.
            "00-zzf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            // 33 chars.
            "00-4bf92f3577b34da6a3ce929d0e0e47361-00f067aa0ba902b7-01",
        ] {
            assert!(
                trace_id_from_traceparent(bad).is_none(),
                "accepted malformed traceparent: {bad:?}"
            );
        }
    }

    /// The span constructors above spell their field names as macro
    /// identifiers, which the compiler cannot check against
    /// [`crate::field`]'s constants. This is the tripwire: rename a constant
    /// without renaming the identifier and the vocabulary silently forks.
    #[test]
    fn span_field_identifiers_match_the_vocabulary() {
        let src = include_str!("span.rs");
        for (ident, konst) in [
            ("request_id =", field::REQUEST_ID),
            ("trace_id =", field::TRACE_ID),
            ("session_id =", field::SESSION_ID),
            ("tenant_id =", field::TENANT_ID),
            ("plane =", field::PLANE),
            ("method =", field::METHOD),
            ("route =", field::ROUTE),
            ("host =", field::HOST),
            ("tool =", field::TOOL),
            ("tool_call_id =", field::TOOL_CALL_ID),
        ] {
            assert!(
                src.contains(ident),
                "span constructors no longer record {ident:?}"
            );
            assert_eq!(
                ident.trim_end_matches(" ="),
                konst,
                "the macro identifier and the vocabulary constant have diverged"
            );
        }
    }
}
