//! fluidbox-obs — structured, redacted, correlated logging for the control plane.
//!
//! See `docs/hosted/observability.md` for the operator view. This module doc is
//! the engineering rationale.
//!
//! # The problem this solves
//!
//! Before this crate the control plane logged with bare `tracing::warn!("session
//! {id}: …")` calls: ~250 of them across ~114k lines, every one a formatted
//! string, none with structured fields, none correlated, none filtered for
//! secrets, and with entire planes dark (the whole public API, the permission
//! gate, the broker, the OAuth dance). That is enough to read a single incident
//! by eye on one replica and nothing more. It cannot answer "what happened to
//! run X", "which tenant is driving this load", "why was this tool denied", or
//! "is this 502 ours or the upstream's" — and it had no filter between a
//! credential-bearing error string and stdout.
//!
//! # The four properties
//!
//! 1. **Structured.** Every record is a JSON object with a stable schema
//!    ([`format`]). Fields are typed key/values, not prose, so an aggregator can
//!    index and an operator can filter.
//! 2. **Correlated.** Every record carries the ids of the work it belongs to,
//!    inherited from the enclosing spans ([`span`]) — `request_id` on anything
//!    inside an HTTP request, `session_id` on anything inside a run, plus
//!    `trace_id`/`span_id` in the W3C shape so the logs join a trace later
//!    without a schema change.
//! 3. **Redacted.** Every value written passes through [`redact`] — by shape
//!    (patterns) and by position (field-name deny list) — because logs are an
//!    egress with the same hazard as the ledger and none of its type-level
//!    guarantee.
//! 4. **Bounded.** Field and line lengths are capped and per-callsite rates are
//!    limited ([`throttle`]), because the classic production logging failure is
//!    not too little output, it is a hot loop that fills the disk and buries the
//!    signal.
//!
//! # Why hand-rolled formatters, and no OpenTelemetry
//!
//! Two deliberate choices, both matching the doctrine already stated in
//! `fluidbox-server::metrics` ("a control plane needs perhaps a dozen counters …
//! that is three small lock-free primitives and one text renderer, all here, all
//! auditable in one file"):
//!
//! * **The formatters are ours** ([`format`]) rather than
//!   `tracing_subscriber`'s JSON layer. This is a security property, not a taste
//!   one: redaction is only a guarantee if EVERY byte that reaches the writer
//!   passes through code that scrubs. Owning the formatter makes that
//!   structural — there is no field-rendering path that bypasses it — instead of
//!   a convention someone can forget. It also costs zero new dependencies
//!   (`tracing-serde` and the `json` feature are not pulled in).
//! * **No `opentelemetry` stack.** It would add a large dependency tree, a
//!   background exporter, and a second configuration surface for a deployment
//!   that today ships logs to stdout. Instead the schema emits `trace_id` and
//!   `span_id` in the W3C hex shape, and honours an inbound `traceparent`
//!   header, so a deployment that later runs a collector can join these records
//!   to spans it already has. The forward compatibility is in the DATA, which is
//!   the part that is expensive to change later.
//!
//! # Cost
//!
//! A clean log line allocates nothing for redaction (one `RegexSet` pass,
//! [`Cow::Borrowed`] out). Disabled levels cost a callsite check, as always with
//! `tracing`. The throttle is a sharded map lookup on a `'static` callsite
//! identifier. The expensive part of logging in this system remains what it
//! always was: rendering the message.

pub mod capture;
pub mod config;
pub mod field;
pub mod format;
pub mod init;
pub mod redact;
pub mod span;
pub mod stats;
pub mod throttle;
pub mod timing;

pub use config::LogConfig;
pub use format::{Format, Limits};
pub use init::{init, subscriber_with_writer, LogHandle};
pub use redact::{sensitive_field, url_for_log, url_host, Redactor, PLACEHOLDER};
pub use timing::Stopwatch;
