//! Building and installing the subscriber.
//!
//! Two entry points, and the difference matters:
//!
//! * [`init`] installs a global subscriber writing to stdout. A process calls it
//!   once, at boot, before anything logs.
//! * [`subscriber_with_writer`] builds the same stack over a caller-supplied
//!   sink without installing it, so tests can assert on real output through the
//!   real formatter. Testing logging against a mock formatter proves nothing;
//!   the bugs live in the formatter.

use crate::config::LogConfig;
use crate::format::{ObsLayer, Statics};
use crate::throttle::Throttle;
use std::sync::Arc;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::EnvFilter;

/// Kept by the caller after [`init`] so the parts of the subsystem that outlive
/// construction stay reachable — chiefly the suppression report, which is
/// otherwise unrecoverable once the layer is inside the subscriber.
#[derive(Clone)]
pub struct LogHandle {
    throttle: Arc<Throttle>,
    cfg: LogConfig,
}

impl LogHandle {
    /// Drain the per-callsite suppression counts since the last call. The server
    /// runs this on a timer and logs one line when it is non-empty.
    pub fn throttle_report(&self) -> Vec<(crate::throttle::CallsiteKey, u64)> {
        self.throttle.report()
    }

    /// The resolved configuration, for the boot banner and for `just doctor`.
    pub fn config(&self) -> &LogConfig {
        &self.cfg
    }
}

/// The filter directive that keeps correlation alive.
///
/// A span whose own level fails the filter is never created, and a span that is
/// never created attaches no fields — so under `RUST_LOG=error` the surviving
/// ERROR records would arrive stripped of `request_id` and `session_id`,
/// precisely when context is scarcest and matters most. (This is not
/// hypothetical: the `debug_span!("http", …)` this work replaces contributed
/// nothing at the default `info` filter, for exactly this reason.)
///
/// Every correlation span is constructed in [`crate::span`], so pinning that ONE
/// module keeps them alive under any operator filter.
///
/// The narrowness is deliberate. Pinning the whole crate (`fluidbox_obs=trace`)
/// would also force this crate's own EVENTS past the operator's filter — a
/// module that is meant to be invisible would become the one thing `RUST_LOG=error`
/// could not silence. One module, spans only, nothing else.
const CORRELATION_PIN: &str = "fluidbox_obs::span=trace";

fn build_filter(directives: &str) -> Result<EnvFilter, String> {
    let filter = EnvFilter::try_new(directives)
        .map_err(|e| format!("invalid log filter '{directives}': {e}"))?;
    let pin = CORRELATION_PIN
        .parse()
        .map_err(|e| format!("internal: correlation pin is not a valid directive: {e}"))?;
    Ok(filter.add_directive(pin))
}

fn statics(cfg: &LogConfig) -> Statics {
    Statics {
        service: cfg.service.clone(),
        version: cfg.version.clone(),
        instance: cfg.instance.clone(),
        pid: std::process::id(),
    }
}

fn layer<W>(cfg: &LogConfig, writer: W) -> ObsLayer<W> {
    ObsLayer::new(cfg.format, writer, statics(cfg))
        .with_limits(cfg.limits)
        .with_throttle(cfg.throttle_per_sec)
        .with_ansi(cfg.ansi)
        .with_location(cfg.location)
        .with_thread_names(cfg.thread_names)
}

/// Install the global subscriber. Call once, at the top of `main`.
///
/// Returns an error rather than panicking on a bad filter so the caller can fail
/// boot the way it fails every other bad configuration value — with a message
/// naming the variable.
pub fn init(cfg: &LogConfig) -> Result<LogHandle, String> {
    let filter = build_filter(&cfg.filter)?;
    let l = layer(cfg, std::io::stdout);
    let handle = LogHandle {
        throttle: l.throttle_handle(),
        cfg: cfg.clone(),
    };
    tracing::subscriber::set_global_default(tracing_subscriber::registry().with(filter).with(l))
        .map_err(|e| format!("a tracing subscriber is already installed: {e}"))?;
    Ok(handle)
}

/// Build (but do not install) the same stack over `writer`.
///
/// Used with [`crate::capture::CaptureWriter`] and
/// `tracing::subscriber::with_default` to assert on real emitted bytes.
pub fn subscriber_with_writer<W>(
    cfg: &LogConfig,
    writer: W,
) -> Result<(impl tracing::Subscriber + Send + Sync, LogHandle), String>
where
    W: for<'a> tracing_subscriber::fmt::MakeWriter<'a> + Send + Sync + 'static,
{
    let filter = build_filter(&cfg.filter)?;
    let l = layer(cfg, writer);
    let handle = LogHandle {
        throttle: l.throttle_handle(),
        cfg: cfg.clone(),
    };
    Ok((tracing_subscriber::registry().with(filter).with(l), handle))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::CaptureWriter;
    use crate::config::LogConfig;
    use crate::format::Format;
    use crate::redact::secret_corpus;

    fn cfg(format: Format, filter: &str) -> LogConfig {
        LogConfig {
            format,
            filter: filter.to_string(),
            ansi: false,
            location: false,
            thread_names: false,
            throttle_per_sec: 0,
            service: "fluidbox-test".into(),
            instance: "test-instance".into(),
            ..LogConfig::default()
        }
    }

    /// Run `f` with a capturing subscriber installed for this thread only, and
    /// return what was written.
    fn capture(cfg: &LogConfig, f: impl FnOnce()) -> CaptureWriter {
        let w = CaptureWriter::new();
        let (sub, _h) = subscriber_with_writer(cfg, w.clone()).expect("subscriber builds");
        tracing::subscriber::with_default(sub, f);
        w
    }

    /// **The security property, end to end.** Every credential family, driven
    /// through every shape a real callsite uses — a bare field, an interpolated
    /// message, a `Debug` value, a span field inherited by a nested record, a
    /// sensitively-named field — and none of it reaches the sink.
    ///
    /// This is the test that would have to fail for a credential to appear in a
    /// log aggregator.
    #[test]
    fn no_credential_family_reaches_the_sink_by_any_route() {
        for (family, text, must_go) in secret_corpus() {
            let c = cfg(Format::Json, "trace");
            let t = text.clone();
            let w = capture(&c, || {
                // 1. as an interpolated message
                tracing::info!("upstream said: {t}");
                // 2. as a structured field value
                tracing::warn!(detail = %t, "call failed");
                // 3. as a Debug value
                tracing::error!(payload = ?t, "rejected");
                // 4. inherited from a span, by a record that never mentions it
                let span = tracing::info_span!("outer", context = %t);
                let _g = span.enter();
                tracing::info!("inside the span");
                // 5. under a field name the deny-list covers
                tracing::info!(client_secret = %t, "sealed");
            });
            let out = w.contents();
            assert!(
                !out.contains(&must_go),
                "{family}: reached the log sink\n  wanted gone: {must_go}\n  output:\n{out}"
            );
        }
    }

    /// A sensitively-named field is blanked WHOLESALE — the value is never
    /// examined, so a shapeless secret (a raw KEK, a random password) is caught
    /// by position even though no pattern would ever match it.
    #[test]
    fn sensitively_named_fields_are_blanked_whatever_their_shape() {
        let c = cfg(Format::Json, "trace");
        let w = capture(&c, || {
            tracing::info!(
                password = "correct-horse-battery-staple",
                client_secret = "9f2c4a7e11b3d865",
                token_id = "018f2c3d-0000-7000-8000-000000000000",
                "connected"
            );
        });
        let rec = &w.json()[0];
        assert_eq!(rec["password"], crate::PLACEHOLDER);
        assert_eq!(rec["client_secret"], crate::PLACEHOLDER);
        // …and the structural join key beside it survives, or correlation dies.
        assert_eq!(rec["token_id"], "018f2c3d-0000-7000-8000-000000000000");
    }

    /// The JSON envelope has the shape the schema documents, and every record is
    /// independently parsable.
    #[test]
    fn json_records_carry_the_documented_envelope() {
        let c = cfg(Format::Json, "trace");
        let w = capture(&c, || tracing::info!(session_id = "s1", "hello"));
        let recs = w.json();
        assert_eq!(recs.len(), 1);
        let r = &recs[0];
        assert_eq!(r["level"], "info");
        assert_eq!(r["msg"], "hello");
        assert_eq!(r["service"], "fluidbox-test");
        assert_eq!(r["instance"], "test-instance");
        assert_eq!(r["session_id"], "s1");
        assert!(r["target"].as_str().unwrap().starts_with("fluidbox_obs"));
        assert!(r["ts"].as_str().unwrap().ends_with('Z'), "UTC, RFC3339");
        assert!(r["pid"].is_number());
    }

    /// Span fields are inherited by records that never mention them — the whole
    /// point of correlation.
    #[test]
    fn records_inherit_the_ids_of_every_enclosing_span() {
        let c = cfg(Format::Json, "trace");
        let w = capture(&c, || {
            let outer = crate::span::request("public", "POST", "/v1/sessions", "req-1", "t-1");
            let _o = outer.enter();
            let inner = crate::span::run("sess-9", "tenant-3");
            let _i = inner.enter();
            tracing::info!("deep inside");
        });
        let r = &w.json()[0];
        assert_eq!(r["request_id"], "req-1");
        assert_eq!(r["trace_id"], "t-1");
        assert_eq!(r["route"], "/v1/sessions");
        assert_eq!(r["session_id"], "sess-9");
        assert_eq!(r["tenant_id"], "tenant-3");
        assert_eq!(r["span"], "run", "the innermost span names the record");
        assert_eq!(
            r["spans"],
            serde_json::json!(["http", "run"]),
            "root → leaf"
        );
    }

    /// **The regression this whole design turns on.** The pre-existing
    /// `debug_span!("http", …)` contributed nothing at the default filter,
    /// because a span below the filter attaches no fields. Correlation must
    /// survive a filter tightened all the way to `error`, which is exactly when
    /// an operator has tightened it and still needs to know whose request broke.
    #[test]
    fn correlation_survives_a_filter_that_only_admits_errors() {
        let c = cfg(Format::Json, "error");
        let w = capture(&c, || {
            let s = crate::span::request("public", "GET", "/v1/runs/{id}", "req-42", "trace-42");
            let _g = s.enter();
            tracing::info!("suppressed by the filter");
            tracing::error!(error_kind = "db", "the one line that survives");
        });
        let recs = w.json();
        assert_eq!(recs.len(), 1, "only the error passed the filter");
        assert_eq!(recs[0]["msg"], "the one line that survives");
        assert_eq!(
            recs[0]["request_id"], "req-42",
            "the surviving error still knows which request it belongs to"
        );
        assert_eq!(recs[0]["route"], "/v1/runs/{id}");
    }

    /// The event's statement of a fact beats the span's, and the key appears
    /// exactly once — a JSON object with two `session_id` keys is ambiguous at
    /// best and rejected at worst.
    #[test]
    fn an_event_field_overrides_the_span_field_of_the_same_name_exactly_once() {
        let c = cfg(Format::Json, "trace");
        let w = capture(&c, || {
            let s = crate::span::run("outer-session", "t1");
            let _g = s.enter();
            tracing::info!(session_id = "inner-session", "more specific");
        });
        let line = &w.lines()[0];
        assert_eq!(line.matches("\"session_id\"").count(), 1, "{line}");
        assert_eq!(w.json()[0]["session_id"], "inner-session");
    }

    /// A field named like an envelope key is renamed, not dropped and not
    /// allowed to shadow the envelope.
    #[test]
    fn fields_colliding_with_the_envelope_are_renamed() {
        let c = cfg(Format::Json, "trace");
        let w = capture(&c, || {
            tracing::info!(level = "critical", msg = "shadow", "real message")
        });
        let r = &w.json()[0];
        assert_eq!(r["level"], "info", "the envelope wins");
        assert_eq!(r["msg"], "real message");
        assert_eq!(r["level_"], "critical", "and the field is preserved");
        assert_eq!(r["msg_"], "shadow");
    }

    /// Errors are logged with their whole `source()` chain. `pool timed out`
    /// alone does not identify a cause; `… : connection refused` does.
    #[test]
    fn error_values_are_logged_with_their_full_cause_chain() {
        #[derive(Debug)]
        struct Inner;
        impl std::fmt::Display for Inner {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "connection refused")
            }
        }
        impl std::error::Error for Inner {}
        #[derive(Debug)]
        struct Outer(Inner);
        impl std::fmt::Display for Outer {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "pool timed out")
            }
        }
        impl std::error::Error for Outer {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                Some(&self.0)
            }
        }

        let c = cfg(Format::Json, "trace");
        let w = capture(&c, || {
            let e = Outer(Inner);
            tracing::error!(error = &e as &dyn std::error::Error, "acquire failed");
        });
        assert_eq!(w.json()[0]["error"], "pool timed out: connection refused");
    }

    /// Text output carries the same data — same redaction, same ids — laid out
    /// for a human. A dev-format log that quietly skips redaction would be a
    /// leak on every developer's terminal and in every CI artifact.
    #[test]
    fn text_output_is_redacted_and_correlated_too() {
        let c = cfg(Format::Text, "trace");
        let secret = format!("ghp_{}", "z".repeat(36));
        let s2 = secret.clone();
        let w = capture(&c, || {
            let s = crate::span::run("sess-1", "ten-1");
            let _g = s.enter();
            tracing::warn!(detail = %s2, "push rejected");
        });
        let line = &w.lines()[0];
        assert!(!line.contains(&"z".repeat(36)), "{line}");
        assert!(line.contains("session_id=sess-1"), "{line}");
        assert!(line.contains("[run]"), "{line}");
        assert!(line.contains("push rejected"), "{line}");
        assert!(line.contains(" warn "), "{line}");
    }

    /// A runaway callsite is cut off and the loss is accounted for, rather than
    /// filling the disk.
    #[test]
    fn a_flooding_callsite_is_throttled_and_the_loss_is_reported() {
        let mut c = cfg(Format::Json, "trace");
        c.throttle_per_sec = 5;
        let w = CaptureWriter::new();
        let (sub, handle) = subscriber_with_writer(&c, w.clone()).unwrap();
        tracing::subscriber::with_default(sub, || {
            for i in 0..100 {
                tracing::warn!(attempt = i, "retrying");
            }
        });
        assert_eq!(w.lines().len(), 5, "budget honoured");
        let report = handle.throttle_report();
        assert_eq!(report.len(), 1);
        assert_eq!(report[0].1, 95, "every dropped record is accounted for");
        assert_eq!(
            report[0].0.target, "fluidbox_obs::init::tests",
            "the report NAMES the offending callsite, so an operator can act on it"
        );
        assert!(report[0].0.line.is_some(), "…down to the line");
    }

    /// An oversized value is cut at the ceiling and the record still parses —
    /// a truncated line that no parser accepts loses the fields that DID fit.
    #[test]
    fn oversized_values_are_capped_and_the_record_still_parses() {
        let mut c = cfg(Format::Json, "trace");
        c.limits.max_field_bytes = 256;
        c.limits.max_line_bytes = 4096;
        let w = capture(&c, || {
            tracing::info!(blob = "x".repeat(100_000), "huge");
        });
        let r = &w.json()[0]; // panics if unparsable
        let v = r["blob"].as_str().unwrap();
        assert!(v.len() < 400, "capped, got {} bytes", v.len());
        assert!(v.contains("truncated"), "and says so: {v}");
    }
}
