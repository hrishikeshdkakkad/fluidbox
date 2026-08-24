//! Boot configuration for the logging subsystem.
//!
//! Follows the house convention for configuration in this repository: a
//! malformed value **fails boot** with a message naming the variable and the
//! accepted set, rather than being silently coerced to a default. A logging
//! knob that quietly ignores what the operator typed is how a deployment ends up
//! believing it emits JSON while it emits ANSI-coloured text into an aggregator.
//!
//! # There is no knob to disable redaction
//!
//! Deliberately. The only argument for one is "redaction is hiding something I
//! need", and the redactor is built to keep the diagnostic while removing the
//! secret — a scrubbed connection string still names the host and the role, a
//! scrubbed callback still names the parameter. Against that, a disable switch
//! is a single environment variable between a production deployment and
//! credentials in a third-party log store, and the pressure to flip it arrives
//! exactly when judgement is worst (mid-incident, at 3am). If a specific field
//! is being over-redacted, the fix is a named entry in
//! [`crate::redact::sensitive_field`]'s allow list, reviewed like any other
//! change to a security control.

use crate::format::{Format, Limits};

/// The default filter directive set.
///
/// **`fluidbox_server` sits at `info`, where it used to sit at `debug`.** That
/// is a deliberate change and it goes with this work rather than despite it:
/// the crate now emits far more `debug!` than it did when `debug` was chosen as
/// the default (a handful of lines across the whole binary), so keeping the old
/// default would have turned a quiet default into a firehose. `debug` remains
/// one variable away and is where the step-by-step detail lives.
///
/// The third-party directives suppress transport chatter that carries no
/// control-plane meaning — and `hyper`/`h2` in particular log per-frame at debug.
pub const DEFAULT_FILTER: &str = "info,fluidbox_server=info,fluidbox_db=info,sqlx=warn,\
     hyper=warn,hyper_util=warn,h2=warn,rustls=warn,tower_http=warn,\
     reqwest=warn,bollard=warn,kube=info,aws_config=warn,aws_sdk_kms=warn,aws_smithy_runtime=warn";

/// How much to log, where, and in what shape.
#[derive(Debug, Clone)]
pub struct LogConfig {
    pub format: Format,
    /// An `EnvFilter` directive string.
    pub filter: String,
    pub ansi: bool,
    /// Include `file:line`. Defaults to on for text, off for JSON.
    pub location: bool,
    pub thread_names: bool,
    /// Records per callsite per second before suppression; `0` disables.
    pub throttle_per_sec: u32,
    pub limits: Limits,
    pub service: String,
    pub version: String,
    pub instance: String,
    /// How often the suppression report is emitted, in seconds. `0` disables the
    /// reporter (suppressions are still counted in [`crate::stats`]).
    pub throttle_report_secs: u64,
}

/// Default per-callsite budget.
///
/// Chosen against the actual loops in this codebase rather than as a round
/// number: the tightest retry here re-enters about every two seconds
/// (network-grant re-verification), the sweepers every ten, and the delivery
/// worker backs off — so no healthy path comes within two orders of magnitude of
/// this. What it does catch is the pathological case: a per-request or
/// per-event error that fires as fast as traffic arrives.
pub const DEFAULT_THROTTLE_PER_SEC: u32 = 200;

/// Default suppression-report interval. One line a minute naming the flood is
/// enough to act on and far too little to become a flood itself.
pub const DEFAULT_THROTTLE_REPORT_SECS: u64 = 60;

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            format: Format::Json,
            filter: DEFAULT_FILTER.to_string(),
            ansi: false,
            location: false,
            thread_names: false,
            throttle_per_sec: DEFAULT_THROTTLE_PER_SEC,
            limits: Limits::default(),
            service: "fluidbox".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            instance: "unknown".to_string(),
            throttle_report_secs: DEFAULT_THROTTLE_REPORT_SECS,
        }
    }
}

impl LogConfig {
    /// Read the environment.
    ///
    /// `service` names the binary (`fluidbox-server`, `fluidbox-cli`, …) — it is
    /// an argument rather than an environment variable because it identifies the
    /// program, and a program that can be told it is a different program makes
    /// every downstream query a guess.
    pub fn from_env(service: &str) -> Result<Self, String> {
        let get = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());
        let tty = std::io::IsTerminal::is_terminal(&std::io::stdout());

        let format = match get("FLUIDBOX_LOG_FORMAT").as_deref() {
            None | Some("auto") => {
                // A terminal means a human is reading; a pipe means a collector
                // is. Getting this wrong in either direction is merely annoying,
                // which is why it is the only setting that guesses at all.
                if tty {
                    Format::Text
                } else {
                    Format::Json
                }
            }
            Some("json") => Format::Json,
            Some("text") => Format::Text,
            Some(other) => {
                return Err(format!(
                    "FLUIDBOX_LOG_FORMAT='{other}' is invalid (known: json, text, auto)"
                ))
            }
        };

        // RUST_LOG stays authoritative when set: it is what every Rust operator
        // and every script in `scripts/` already reaches for, and this crate
        // arriving should not invalidate that muscle memory.
        let filter = get("RUST_LOG")
            .or_else(|| get("FLUIDBOX_LOG_LEVEL"))
            .unwrap_or_else(|| DEFAULT_FILTER.to_string());

        let ansi = match get("FLUIDBOX_LOG_COLOR").as_deref() {
            None | Some("auto") => tty && format == Format::Text,
            Some(v) => parse_bool("FLUIDBOX_LOG_COLOR", v)?,
        };

        let location = match get("FLUIDBOX_LOG_LOCATION").as_deref() {
            None => format == Format::Text,
            Some(v) => parse_bool("FLUIDBOX_LOG_LOCATION", v)?,
        };

        let thread_names = match get("FLUIDBOX_LOG_THREAD_NAMES").as_deref() {
            None => false,
            Some(v) => parse_bool("FLUIDBOX_LOG_THREAD_NAMES", v)?,
        };

        let throttle_per_sec = parse_u32(
            "FLUIDBOX_LOG_THROTTLE_PER_SEC",
            get("FLUIDBOX_LOG_THROTTLE_PER_SEC").as_deref(),
            DEFAULT_THROTTLE_PER_SEC,
        )?;
        let throttle_report_secs = parse_u64(
            "FLUIDBOX_LOG_THROTTLE_REPORT_SECS",
            get("FLUIDBOX_LOG_THROTTLE_REPORT_SECS").as_deref(),
            DEFAULT_THROTTLE_REPORT_SECS,
        )?;

        let d = Limits::default();
        let max_field_bytes = parse_usize(
            "FLUIDBOX_LOG_MAX_FIELD_BYTES",
            get("FLUIDBOX_LOG_MAX_FIELD_BYTES").as_deref(),
            d.max_field_bytes,
        )?;
        let max_line_bytes = parse_usize(
            "FLUIDBOX_LOG_MAX_LINE_BYTES",
            get("FLUIDBOX_LOG_MAX_LINE_BYTES").as_deref(),
            d.max_line_bytes,
        )?;
        // A ceiling below the truncation marker cannot produce a parsable line,
        // and one below a field ceiling is incoherent. Both are typos, and both
        // are better caught at boot than discovered in an unparsable log.
        if max_field_bytes < 64 {
            return Err(format!(
                "FLUIDBOX_LOG_MAX_FIELD_BYTES={max_field_bytes} is below the 64-byte floor \
                 (a value that small truncates every field to its marker)"
            ));
        }
        if max_line_bytes < max_field_bytes {
            return Err(format!(
                "FLUIDBOX_LOG_MAX_LINE_BYTES={max_line_bytes} is below \
                 FLUIDBOX_LOG_MAX_FIELD_BYTES={max_field_bytes}: every record would be truncated"
            ));
        }

        Ok(Self {
            format,
            filter,
            ansi,
            location,
            thread_names,
            throttle_per_sec,
            limits: Limits {
                max_field_bytes,
                max_line_bytes,
            },
            service: service.to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            instance: get("FLUIDBOX_LOG_INSTANCE")
                .or_else(|| get("HOSTNAME"))
                .or_else(|| get("POD_NAME"))
                .or_else(read_hostname)
                .unwrap_or_else(|| "unknown".to_string()),
            throttle_report_secs,
        })
    }
}

/// Last resort for the replica identity. Kubernetes sets `HOSTNAME` to the pod
/// name and Docker sets it to the container id, so this is only reached for a
/// bare-metal process — where the kernel's value is the right answer.
fn read_hostname() -> Option<String> {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .or_else(|_| std::fs::read_to_string("/etc/hostname"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn parse_bool(name: &str, raw: &str) -> Result<bool, String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        other => Err(format!(
            "{name}='{other}' is invalid (known: 1/true/yes/on, 0/false/no/off, auto)"
        )),
    }
}

fn parse_u32(name: &str, raw: Option<&str>, default: u32) -> Result<u32, String> {
    match raw {
        None => Ok(default),
        Some(v) => v
            .trim()
            .parse()
            .map_err(|_| format!("{name}='{v}' is not a non-negative integer")),
    }
}

fn parse_u64(name: &str, raw: Option<&str>, default: u64) -> Result<u64, String> {
    match raw {
        None => Ok(default),
        Some(v) => v
            .trim()
            .parse()
            .map_err(|_| format!("{name}='{v}' is not a non-negative integer")),
    }
}

fn parse_usize(name: &str, raw: Option<&str>, default: usize) -> Result<usize, String> {
    match raw {
        None => Ok(default),
        Some(v) => v
            .trim()
            .parse()
            .map_err(|_| format!("{name}='{v}' is not a non-negative integer")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The parse helpers are what stand between a typo and a silently wrong
    /// logging setup, so they are tested directly — `from_env` itself reads
    /// process-global state and cannot be exercised concurrently.
    #[test]
    fn booleans_accept_the_usual_spellings_and_reject_the_rest() {
        for t in ["1", "true", "TRUE", "yes", "on"] {
            assert!(parse_bool("X", t).unwrap(), "{t}");
        }
        for f in ["0", "false", "No", "off"] {
            assert!(!parse_bool("X", f).unwrap(), "{f}");
        }
        let e = parse_bool("FLUIDBOX_LOG_COLOR", "maybe").unwrap_err();
        assert!(e.contains("FLUIDBOX_LOG_COLOR"), "names the variable: {e}");
        assert!(e.contains("known:"), "states the accepted set: {e}");
    }

    #[test]
    fn numeric_knobs_reject_garbage_by_name() {
        let e = parse_u32("FLUIDBOX_LOG_THROTTLE_PER_SEC", Some("lots"), 1).unwrap_err();
        assert!(e.contains("FLUIDBOX_LOG_THROTTLE_PER_SEC"), "{e}");
        assert_eq!(parse_u32("X", None, 7).unwrap(), 7);
    }

    /// The default filter must actually parse as an `EnvFilter` directive set.
    /// A typo here disables logging for a whole crate and nothing else fails.
    #[test]
    fn the_default_filter_is_valid() {
        tracing_subscriber::EnvFilter::try_new(DEFAULT_FILTER)
            .expect("DEFAULT_FILTER must be a valid EnvFilter directive set");
    }

    /// The default filter must not leave `fluidbox_server` above `info`, or the
    /// instrumentation this whole change adds is invisible out of the box.
    #[test]
    fn the_default_filter_keeps_the_server_at_info() {
        assert!(
            DEFAULT_FILTER.contains("fluidbox_server=info"),
            "{DEFAULT_FILTER}"
        );
    }
}
