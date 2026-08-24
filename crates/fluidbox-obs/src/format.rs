//! The record formatter — and the single write path.
//!
//! # Why this is a whole `Layer` rather than a `FormatEvent` impl
//!
//! `tracing_subscriber::fmt` splits formatting across two traits (`FormatFields`
//! for span/event fields, `FormatEvent` for the envelope) and stashes the
//! rendered field text in span extensions as an opaque string. That split is
//! fine for a text log and wrong for this one, for two reasons:
//!
//! 1. **Redaction has to be structural.** The security claim is "no value
//!    reaches the sink unscrubbed". That is only provable if there is exactly
//!    ONE place bytes are produced. Splitting the job across two traits and a
//!    pre-rendered extension string leaves seams — and a seam in a redaction
//!    guarantee is the same as no guarantee.
//! 2. **Duplicate keys.** Merging a span's fields with an event's needs the
//!    KEYS, and an opaque pre-rendered fragment does not have them. Emitting a
//!    JSON object with `session_id` twice (once from the span, once from the
//!    event) is invalid to strict parsers and ambiguous to lenient ones. Keeping
//!    typed field vectors in the extension makes "the event wins" a two-line
//!    rule instead of a string-parsing problem.
//!
//! So the layer owns everything: it captures span fields as typed values at span
//! creation (scrubbing ONCE there, not once per record that inherits them),
//! merges them at event time, and writes one line with one `write_all`.
//!
//! # The record schema
//!
//! One flat JSON object per line. Envelope keys ([`RESERVED`]) are stamped by
//! this module; everything else is a field from the event or an enclosing span,
//! named from [`crate::field`].
//!
//! ```text
//! {"ts":"2026-08-24T09:12:33.481920Z","level":"info",
//!  "target":"fluidbox_server::orchestrator","msg":"run transitioned",
//!  "service":"fluidbox-server","version":"0.8.0","instance":"fbx-7d9c",
//!  "pid":1,"span":"run","spans":["http","run"],"span_id":"00000000000004d2",
//!  "request_id":"018f…","session_id":"018f…","tenant_id":"018f…",
//!  "from":"provisioning","to":"running","duration_ms":812}
//! ```
//!
//! Flat, not nested: one index level, no ambiguity about whether `http.status`
//! is an object, and every aggregator handles it identically.
//!
//! # Ordering and collisions
//!
//! Fields are written span-context first (root → leaf), then the event's own —
//! so a human reading text output sees the correlation ids before the specifics.
//! When a name appears in both, **the event wins and the span copy is dropped**
//! (the innermost, most specific statement of a fact is the true one). A field
//! whose name collides with a reserved envelope key is written with a trailing
//! underscore rather than shadowing the envelope.
//!
//! # Failure posture
//!
//! Logging never panics and never propagates. A write error increments
//! [`crate::stats`] and the record is dropped: a full disk must not take down a
//! control plane, and an operator learns about it from `fluidbox_log_write_errors`
//! rather than from an outage.

use crate::redact::{sensitive_field, Redactor, PLACEHOLDER};
use crate::stats::STATS;
use crate::throttle::{CallsiteKey, Throttle};
use std::fmt::Write as _;
use std::sync::Arc;
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::registry::LookupSpan;

/// Envelope keys this module writes itself. A field with one of these names is
/// emitted with a trailing underscore instead of shadowing the envelope.
pub const RESERVED: &[&str] = &[
    "ts", "level", "target", "msg", "service", "version", "instance", "pid", "thread", "file",
    "line", "span", "spans", "span_id",
];

/// Output shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// One JSON object per line — the production default. Machine-parsable,
    /// stable schema, safe to ship to an aggregator.
    Json,
    /// Human-readable single line — the development default. Same data, same
    /// redaction, laid out for eyes instead of indexes.
    Text,
}

/// Size ceilings. Both exist because an unbounded log line is an availability
/// problem: a single `Debug` of a large structure can produce megabytes, and a
/// log pipeline that must buffer it will drop everything around it.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Longest rendered value for one field, in bytes. Overlong values are cut
    /// at a UTF-8 boundary and marked.
    pub max_field_bytes: usize,
    /// Longest complete record, in bytes. A record over the ceiling is cut and
    /// marked; for JSON the cut is made so the object still closes, because a
    /// truncated line that no longer parses loses the fields that DID fit.
    pub max_line_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            // Comfortably larger than any legitimate field here (the longest are
            // error chains and route patterns) and far smaller than a runaway
            // `Debug`.
            max_field_bytes: 8 * 1024,
            max_line_bytes: 64 * 1024,
        }
    }
}

/// Process-constant envelope values.
#[derive(Debug, Clone)]
pub struct Statics {
    pub service: String,
    pub version: String,
    /// Replica identity. Load-bearing for everything replica-local in this
    /// system (the orchestrator lease, the MCP session registry, the in-memory
    /// rate tier) — without it, two replicas' logs are indistinguishable
    /// exactly where their behaviour differs.
    pub instance: String,
    pub pid: u32,
}

/// A recorded field value, captured in a type the writer can emit directly.
///
/// Strings are scrubbed AT CAPTURE, which matters for spans: a span's fields are
/// scrubbed once when the span is created rather than on every one of the
/// possibly thousands of records that inherit them.
#[derive(Debug, Clone)]
enum Val {
    Str(String),
    /// An already-rendered numeric literal. Kept as text so `i128`, `u128` and
    /// `f64` all take one path and no precision is lost round-tripping through
    /// `f64` — and so non-finite floats (invalid in JSON) can be diverted to
    /// [`Val::Str`] at capture instead of producing an unparsable line.
    Num(String),
    Bool(bool),
}

/// Typed field capture for one span or event.
#[derive(Debug, Default, Clone)]
struct Fields(Vec<(&'static str, Val)>);

impl Fields {
    fn contains(&self, name: &str) -> bool {
        self.0.iter().any(|(k, _)| *k == name)
    }
}

/// Visits `tracing` values into [`Fields`], applying both redaction mechanisms.
struct Visitor<'a> {
    out: &'a mut Fields,
    redactor: &'a Redactor,
    limits: Limits,
    /// The `message` field, pulled out of the field set into the envelope.
    message: Option<String>,
    redactions: u64,
}

impl<'a> Visitor<'a> {
    fn new(out: &'a mut Fields, redactor: &'a Redactor, limits: Limits) -> Self {
        Self {
            out,
            redactor,
            limits,
            message: None,
            redactions: 0,
        }
    }

    /// Scrub, cap, and record a string-shaped value.
    fn push_str_value(&mut self, field: &Field, raw: String) {
        let name = field.name();
        // Mechanism 1: position. A sensitive NAME means the value is never
        // examined, rendered, or measured — it is replaced outright.
        if sensitive_field(name) {
            self.redactions += 1;
            self.set(name, Val::Str(PLACEHOLDER.to_string()));
            return;
        }
        // Mechanism 2: shape.
        let scrubbed = match self.redactor.scrub(&raw) {
            std::borrow::Cow::Borrowed(_) => raw,
            std::borrow::Cow::Owned(s) => {
                self.redactions += 1;
                s
            }
        };
        let capped = cap(scrubbed, self.limits.max_field_bytes);
        if name == "message" {
            self.message = Some(capped);
        } else {
            self.set(name, Val::Str(capped));
        }
    }

    /// Record a non-string value, honouring the field-name deny list (a
    /// sensitive name is redacted whatever its type — a numeric `secret` is
    /// still a secret).
    fn push_scalar(&mut self, field: &Field, v: Val) {
        let name = field.name();
        if sensitive_field(name) {
            self.redactions += 1;
            self.set(name, Val::Str(PLACEHOLDER.to_string()));
            return;
        }
        self.set(name, v);
    }

    /// Last write wins for a repeated name within one field set — `tracing`'s
    /// `record()` on an existing span re-states fields, and the newest value is
    /// the true one.
    fn set(&mut self, name: &'static str, v: Val) {
        if let Some(slot) = self.out.0.iter_mut().find(|(k, _)| *k == name) {
            slot.1 = v;
        } else {
            self.out.0.push((name, v));
        }
    }
}

impl Visit for Visitor<'_> {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.push_str_value(field, value.to_string());
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.push_str_value(field, format!("{value:?}"));
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.push_scalar(field, Val::Num(value.to_string()));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.push_scalar(field, Val::Num(value.to_string()));
    }

    fn record_i128(&mut self, field: &Field, value: i128) {
        self.push_scalar(field, Val::Num(value.to_string()));
    }

    fn record_u128(&mut self, field: &Field, value: u128) {
        self.push_scalar(field, Val::Num(value.to_string()));
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        // NaN and ±Infinity are not JSON numbers. Emitting them raw produces a
        // line no parser accepts, so they become strings and stay visible.
        if value.is_finite() {
            self.push_scalar(field, Val::Num(format!("{value}")));
        } else {
            self.push_str_value(field, value.to_string());
        }
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.push_scalar(field, Val::Bool(value));
    }

    /// `tracing::field::display`/`Empty` and explicit nulls.
    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        // The whole chain, not just the outer message: `sqlx::Error: pool
        // timed out` says nothing without its cause. This is the single
        // highest-value thing an error logger can do and the default `Debug`
        // rendering does not do it.
        let mut chain = value.to_string();
        let mut src = value.source();
        while let Some(e) = src {
            let _ = write!(chain, ": {e}");
            src = e.source();
        }
        self.push_str_value(field, chain);
    }
}

/// Truncate on a UTF-8 boundary, marking what was lost. Counting the lost bytes
/// matters: "this was cut" and "this was cut by 4 MB" are different incidents.
fn cap(s: String, max: usize) -> String {
    if s.len() <= max {
        return s;
    }
    STATS.inc_truncations();
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    let dropped = s.len() - end;
    let mut out = s;
    out.truncate(end);
    let _ = write!(out, "…(+{dropped} bytes truncated)");
    out
}

/// Marker written into a record that hit [`Limits::max_line_bytes`].
const LINE_TRUNCATION_MARK: &str = "…TRUNCATED";

// ── The layer ──────────────────────────────────────────────────────────────

/// The one write path. Owns capture, merge, redaction, formatting and output.
pub struct ObsLayer<W> {
    format: Format,
    writer: W,
    redactor: Redactor,
    limits: Limits,
    statics: Statics,
    throttle: Arc<Throttle>,
    ansi: bool,
    /// Include `file`/`line` in the envelope. On by default for text (a
    /// developer wants to jump to the callsite) and off for JSON (an aggregator
    /// pays per field, the target is usually enough, and the throttle report
    /// names locations when they matter).
    location: bool,
    thread_names: bool,
}

impl<W> ObsLayer<W> {
    pub fn new(format: Format, writer: W, statics: Statics) -> Self {
        Self {
            format,
            writer,
            redactor: Redactor::new(),
            limits: Limits::default(),
            statics,
            throttle: Arc::new(Throttle::new(0)),
            ansi: false,
            location: matches!(format, Format::Text),
            thread_names: false,
        }
    }

    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Install a per-callsite rate limit (`0` disables). See [`crate::throttle`].
    pub fn with_throttle(mut self, per_callsite_per_sec: u32) -> Self {
        self.throttle = Arc::new(Throttle::new(per_callsite_per_sec));
        self
    }

    pub fn with_ansi(mut self, ansi: bool) -> Self {
        self.ansi = ansi;
        self
    }

    pub fn with_location(mut self, on: bool) -> Self {
        self.location = on;
        self
    }

    pub fn with_thread_names(mut self, on: bool) -> Self {
        self.thread_names = on;
        self
    }

    /// A handle to the limiter, so the caller can drain its suppression report
    /// after the layer has been moved into the subscriber. Without this the
    /// report would be unreachable — which is how "we silently dropped 40,000
    /// records" happens.
    pub fn throttle_handle(&self) -> Arc<Throttle> {
        Arc::clone(&self.throttle)
    }
}

impl<S, W> Layer<S> for ObsLayer<W>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    W: for<'a> MakeWriter<'a> + 'static,
{
    /// Capture a span's fields ONCE, scrubbed, as typed values. Every record
    /// emitted inside the span inherits them without re-scrubbing.
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(id) else { return };
        let mut fields = Fields::default();
        let mut v = Visitor::new(&mut fields, &self.redactor, self.limits);
        attrs.record(&mut v);
        let redactions = v.redactions;
        // A span's own `message`, if any, is not part of the envelope of the
        // records inside it; keep it as an ordinary field so it is not lost.
        if let Some(m) = v.message.take() {
            fields.0.push(("span_message", Val::Str(m)));
        }
        STATS.add_redactions(redactions);
        span.extensions_mut().insert(fields);
    }

    /// `Span::record` after creation — merge, newest wins.
    fn on_record(&self, id: &Id, values: &Record<'_>, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(id) else { return };
        let mut ext = span.extensions_mut();
        let Some(fields) = ext.get_mut::<Fields>() else {
            return;
        };
        let mut v = Visitor::new(fields, &self.redactor, self.limits);
        values.record(&mut v);
        STATS.add_redactions(v.redactions);
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        let meta = event.metadata();
        let key = CallsiteKey {
            target: meta.target(),
            file: meta.file(),
            line: meta.line(),
        };
        if !self.throttle.admit(key) {
            return;
        }

        let mut own = Fields::default();
        let mut v = Visitor::new(&mut own, &self.redactor, self.limits);
        event.record(&mut v);
        let message = v.message.take().unwrap_or_default();
        STATS.add_redactions(v.redactions);

        // Span context, root → leaf, minus anything the event restates.
        let mut inherited: Vec<(&'static str, Val)> = Vec::new();
        let mut span_names: Vec<&'static str> = Vec::new();
        let mut innermost_id: Option<u64> = None;
        if let Some(scope) = ctx.event_scope(event) {
            for span in scope.from_root() {
                span_names.push(span.name());
                innermost_id = Some(span.id().into_u64());
                if let Some(f) = span.extensions().get::<Fields>() {
                    for (k, val) in &f.0 {
                        if own.contains(k) {
                            continue; // the event's statement of a fact wins
                        }
                        if let Some(slot) = inherited.iter_mut().find(|(n, _)| n == k) {
                            slot.1 = val.clone(); // inner span wins over outer
                        } else {
                            inherited.push((k, val.clone()));
                        }
                    }
                }
            }
        }

        let mut line = String::with_capacity(320);
        match self.format {
            Format::Json => self.write_json(
                &mut line,
                meta,
                &message,
                &inherited,
                &own,
                &span_names,
                innermost_id,
            ),
            Format::Text => {
                self.write_text(&mut line, meta, &message, &inherited, &own, &span_names)
            }
        }

        if line.len() > self.limits.max_line_bytes {
            STATS.inc_truncations();
            let mut end = self.limits.max_line_bytes.saturating_sub(
                LINE_TRUNCATION_MARK.len() + if self.format == Format::Json { 2 } else { 0 },
            );
            while end > 0 && !line.is_char_boundary(end) {
                end -= 1;
            }
            line.truncate(end);
            line.push_str(LINE_TRUNCATION_MARK);
            // Close the object so the fields that DID fit are still parsable —
            // a truncated JSON line that no parser accepts loses everything,
            // not just the tail.
            if self.format == Format::Json {
                line.push_str("\"}");
            }
        }
        line.push('\n');

        use std::io::Write as _;
        let mut w = self.writer.make_writer_for(meta);
        if w.write_all(line.as_bytes()).is_err() {
            STATS.inc_write_errors();
        } else {
            STATS.inc_emitted();
        }
    }
}

impl<W> ObsLayer<W> {
    #[allow(clippy::too_many_arguments)]
    fn write_json(
        &self,
        out: &mut String,
        meta: &tracing::Metadata<'_>,
        message: &str,
        inherited: &[(&'static str, Val)],
        own: &Fields,
        span_names: &[&'static str],
        span_id: Option<u64>,
    ) {
        out.push('{');
        json_kv_str(out, "ts", &now_rfc3339());
        out.push(',');
        json_kv_str(out, "level", level_str(meta.level()));
        out.push(',');
        json_kv_str(out, "target", meta.target());
        out.push(',');
        json_kv_str(out, "msg", message);
        out.push(',');
        json_kv_str(out, "service", &self.statics.service);
        out.push(',');
        json_kv_str(out, "version", &self.statics.version);
        out.push(',');
        json_kv_str(out, "instance", &self.statics.instance);
        out.push(',');
        let _ = write!(out, "\"pid\":{}", self.statics.pid);
        if let Some(name) = span_names.last() {
            out.push(',');
            json_kv_str(out, "span", name);
        }
        if !span_names.is_empty() {
            out.push_str(",\"spans\":[");
            for (i, n) in span_names.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                json_str(out, n);
            }
            out.push(']');
        }
        if let Some(id) = span_id {
            out.push(',');
            json_kv_str(out, "span_id", &format!("{id:016x}"));
        }
        if self.location {
            if let Some(f) = meta.file() {
                out.push(',');
                json_kv_str(out, "file", f);
            }
            if let Some(l) = meta.line() {
                out.push(',');
                let _ = write!(out, "\"line\":{l}");
            }
        }
        if self.thread_names {
            if let Some(t) = std::thread::current().name() {
                out.push(',');
                json_kv_str(out, "thread", t);
            }
        }
        for (k, v) in inherited.iter().chain(own.0.iter()) {
            out.push(',');
            json_str(out, &safe_key(k));
            out.push(':');
            json_val(out, v);
        }
        out.push('}');
    }

    fn write_text(
        &self,
        out: &mut String,
        meta: &tracing::Metadata<'_>,
        message: &str,
        inherited: &[(&'static str, Val)],
        own: &Fields,
        span_names: &[&'static str],
    ) {
        let (lvl, colour) = (level_str(meta.level()), level_colour(meta.level()));
        let _ = write!(out, "{} ", now_rfc3339());
        if self.ansi {
            let _ = write!(out, "\x1b[{colour}m{lvl:>5}\x1b[0m ");
        } else {
            let _ = write!(out, "{lvl:>5} ");
        }
        if !span_names.is_empty() {
            let _ = write!(out, "[{}] ", span_names.join(">"));
        }
        let _ = write!(out, "{}: {message}", meta.target());
        for (k, v) in inherited.iter().chain(own.0.iter()) {
            out.push(' ');
            out.push_str(&safe_key(k));
            out.push('=');
            match v {
                Val::Str(s) => {
                    // Quote only when the value would otherwise be ambiguous —
                    // unquoted is far more readable and most values are single
                    // tokens (ids, statuses, verdicts).
                    if s.is_empty() || s.contains(' ') || s.contains('"') {
                        json_str(out, s);
                    } else {
                        out.push_str(s);
                    }
                }
                Val::Num(n) => out.push_str(n),
                Val::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            }
        }
        if self.location {
            if let (Some(f), Some(l)) = (meta.file(), meta.line()) {
                let _ = write!(out, " at {f}:{l}");
            }
        }
    }
}

/// Rename a field that would shadow an envelope key. Returning `Cow` keeps the
/// common case allocation-free.
fn safe_key(k: &str) -> std::borrow::Cow<'_, str> {
    if RESERVED.contains(&k) {
        std::borrow::Cow::Owned(format!("{k}_"))
    } else {
        std::borrow::Cow::Borrowed(k)
    }
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
}

fn level_str(l: &Level) -> &'static str {
    match *l {
        Level::TRACE => "trace",
        Level::DEBUG => "debug",
        Level::INFO => "info",
        Level::WARN => "warn",
        Level::ERROR => "error",
    }
}

fn level_colour(l: &Level) -> &'static str {
    match *l {
        Level::TRACE => "90",
        Level::DEBUG => "36",
        Level::INFO => "32",
        Level::WARN => "33",
        Level::ERROR => "31",
    }
}

/// Write `s` as a JSON string literal.
///
/// Fast path first: a string with nothing to escape is copied verbatim inside
/// quotes, which is the overwhelming majority of values here (ids, statuses,
/// route patterns). Only when an escape is genuinely needed does this fall back
/// to `serde_json`, whose escaping is correct for control characters and every
/// other case a hand-rolled version gets wrong — and getting it wrong means a
/// value containing `"` splits one record into two, which is a log-injection
/// bug, not a cosmetic one.
fn json_str(out: &mut String, s: &str) {
    if s.bytes().all(|b| b >= 0x20 && b != b'"' && b != b'\\') {
        out.push('"');
        out.push_str(s);
        out.push('"');
        return;
    }
    match serde_json::to_string(s) {
        Ok(q) => out.push_str(&q),
        // Unreachable for a `&str` (always valid JSON), but logging must never
        // panic: emit an empty string rather than an unterminated one.
        Err(_) => out.push_str("\"\""),
    }
}

fn json_kv_str(out: &mut String, k: &str, v: &str) {
    json_str(out, k);
    out.push(':');
    json_str(out, v);
}

fn json_val(out: &mut String, v: &Val) {
    match v {
        Val::Str(s) => json_str(out, s),
        Val::Num(n) => out.push_str(n),
        Val::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserved_keys_are_unique_and_flat() {
        let mut seen = std::collections::BTreeSet::new();
        for k in RESERVED {
            assert!(seen.insert(*k), "{k} listed twice");
            assert!(!k.contains('.'), "{k}: the schema is flat");
        }
    }

    #[test]
    fn colliding_field_names_are_suffixed_not_dropped() {
        assert_eq!(safe_key("level"), "level_");
        assert_eq!(safe_key("msg"), "msg_");
        assert_eq!(safe_key("session_id"), "session_id");
    }

    /// A value containing a quote must not be able to close the JSON string and
    /// inject a sibling key — the log-injection case.
    #[test]
    fn quotes_and_control_bytes_cannot_break_out_of_a_json_string() {
        let mut s = String::new();
        json_str(&mut s, r#"a" ,"injected":"x"#);
        let parsed: serde_json::Value = serde_json::from_str(&s).expect("valid JSON string");
        assert_eq!(parsed.as_str().unwrap(), r#"a" ,"injected":"x"#);

        let mut s2 = String::new();
        json_str(&mut s2, "line\nbreak\ttab\u{7}bell");
        let parsed2: serde_json::Value = serde_json::from_str(&s2).expect("valid JSON string");
        assert_eq!(parsed2.as_str().unwrap(), "line\nbreak\ttab\u{7}bell");
    }

    #[test]
    fn clean_strings_take_the_fast_path_verbatim() {
        let mut s = String::new();
        json_str(&mut s, "018f2c3d-running");
        assert_eq!(s, "\"018f2c3d-running\"");
    }

    /// Truncation must never split a multi-byte character — a cut inside a UTF-8
    /// sequence produces bytes no JSON parser will accept.
    #[test]
    fn field_truncation_respects_utf8_boundaries() {
        let s = "é".repeat(100); // 2 bytes each
        let out = cap(s, 15);
        assert!(out.starts_with('é'));
        assert!(out.contains("truncated"));
        // The prefix before the marker must still be valid UTF-8 (it is, by
        // construction, or this string would not exist) and end cleanly.
        let prefix = out.split('…').next().unwrap();
        assert_eq!(prefix.len() % 2, 0, "cut mid-character");
    }

    #[test]
    fn short_values_are_returned_untouched() {
        assert_eq!(cap("short".to_string(), 100), "short");
    }
}
