//! An in-memory sink, for tests.
//!
//! Published (not `#[cfg(test)]`) on purpose: the properties worth testing about
//! logging are mostly properties of OTHER crates' instrumentation — "the gate
//! logs a verdict", "the request id survives into the handler's records", "this
//! error path never prints the credential". Those tests live in
//! `fluidbox-server`, so they need a sink they can assert on, and a
//! test-only-in-this-crate helper would be invisible to them.
//!
//! It is deliberately not suitable for production use (unbounded growth, a lock
//! per write) and says so in the type name.

use std::io;
use std::sync::{Arc, Mutex};
use tracing_subscriber::fmt::MakeWriter;

/// A `MakeWriter` that accumulates everything written into memory.
#[derive(Clone, Default)]
pub struct CaptureWriter {
    buf: Arc<Mutex<Vec<u8>>>,
}

impl CaptureWriter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Everything written so far, as UTF-8. Invalid bytes are impossible (the
    /// formatter only writes `String`s) but are lossily replaced rather than
    /// panicking, because a test helper that panics obscures the failure it was
    /// meant to report.
    pub fn contents(&self) -> String {
        let g = self.buf.lock().unwrap_or_else(|e| e.into_inner());
        String::from_utf8_lossy(&g).into_owned()
    }

    /// Written records, one per line, empty lines dropped.
    pub fn lines(&self) -> Vec<String> {
        self.contents()
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| l.to_string())
            .collect()
    }

    /// Written records parsed as JSON. Panics with the offending line if one
    /// does not parse — for a JSON-format subscriber that is a genuine bug in
    /// the formatter and the loudest possible failure is the right one.
    pub fn json(&self) -> Vec<serde_json::Value> {
        self.lines()
            .into_iter()
            .map(|l| {
                serde_json::from_str(&l)
                    .unwrap_or_else(|e| panic!("emitted line is not valid JSON ({e}): {l}"))
            })
            .collect()
    }

    /// True when `needle` appears anywhere in the captured output. The negative
    /// form is the one that matters: `assert!(!w.contains(secret))`.
    pub fn contains(&self, needle: &str) -> bool {
        self.contents().contains(needle)
    }

    pub fn clear(&self) {
        self.buf.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }
}

impl io::Write for CaptureWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buf
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for CaptureWriter {
    type Writer = CaptureWriter;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}
