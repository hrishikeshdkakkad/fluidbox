//! Timed HTTP against the deployment under test.
//!
//! Every request goes through `timed`, so no call site can forget to record a
//! sample, and a transport failure is recorded with the same fidelity as a
//! status — a load run where 40% of requests never got a status line and were
//! silently dropped from the histogram would report a beautiful p99.

use crate::metrics::{classify_reqwest, classify_response, record_into, Outcome, SharedRecorder};
use anyhow::{Context, Result};
use serde_json::Value;
use std::time::{Duration, Instant};

#[derive(Clone)]
pub struct Http {
    pub client: reqwest::Client,
    pub base: String,
    pub admin_token: String,
    pub rec: SharedRecorder,
}

/// One completed request as the CALLER sees it.
///
/// Latency is deliberately absent: it is already in the recorder, and a second
/// copy invites a scenario to compute its own percentiles from a subset of the
/// samples. `outcome` IS here, because a setup step needs to say WHY it failed
/// ("throttled" and "connection refused" are different bug reports).
#[derive(Clone, Debug)]
pub struct Answer {
    pub status: u16,
    pub body: String,
    pub outcome: Outcome,
}

impl Answer {
    pub fn json(&self) -> Option<Value> {
        serde_json::from_str(&self.body).ok()
    }
    /// `d["a"]["b"]` as a string, for pulling ids out of create responses.
    pub fn str_at(&self, path: &[&str]) -> Option<String> {
        let mut v = self.json()?;
        for k in path {
            v = v.get(*k)?.clone();
        }
        v.as_str().map(|s| s.to_string())
    }
    pub fn is_2xx(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

impl Http {
    pub fn new(
        base: &str,
        admin_token: &str,
        timeout: Duration,
        rec: SharedRecorder,
    ) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            // A load harness must be able to hold N sockets open to one host;
            // the default idle-per-host pool would serialize the run and make
            // the harness itself the bottleneck being measured.
            .pool_max_idle_per_host(1024)
            .build()
            .context("building the load-harness HTTP client")?;
        Ok(Self {
            client,
            base: base.trim_end_matches('/').to_string(),
            admin_token: admin_token.to_string(),
            rec,
        })
    }

    /// Send, time, classify, record. The `op` is the reporting bucket.
    ///
    /// A transport failure is NOT an `Err` here: it is an `Answer`-shaped
    /// outcome with status 0. Callers that need "did this succeed" ask
    /// `is_2xx()`; callers that need "what happened to the fleet" read the
    /// recorder. Returning `Err` would tempt a call site into `?`, which would
    /// abandon the rest of a scenario on the first refused connection — exactly
    /// the datum a load test exists to collect.
    pub async fn send(&self, op: &str, req: reqwest::RequestBuilder) -> Answer {
        let started = Instant::now();
        match req.send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let elapsed = started.elapsed();
                let outcome = classify_response(status, &body);
                record_into(&self.rec, op, elapsed, outcome.clone());
                Answer {
                    status,
                    body,
                    outcome,
                }
            }
            Err(e) => {
                let elapsed = started.elapsed();
                let outcome = classify_reqwest(&e);
                record_into(&self.rec, op, elapsed, outcome.clone());
                Answer {
                    status: 0,
                    body: e.to_string(),
                    outcome,
                }
            }
        }
    }

    pub async fn admin_post(&self, op: &str, path: &str, body: Value) -> Answer {
        let req = self
            .client
            .post(format!("{}{path}", self.base))
            .bearer_auth(&self.admin_token)
            .json(&body);
        self.send(op, req).await
    }

    pub async fn admin_get(&self, op: &str, path: &str) -> Answer {
        let req = self
            .client
            .get(format!("{}{path}", self.base))
            .bearer_auth(&self.admin_token);
        self.send(op, req).await
    }

    /// A request on the sandbox-facing internal plane, authenticated by ONE of
    /// the four audience-scoped session tokens.
    pub async fn session_post(&self, op: &str, path: &str, token: &str, body: Value) -> Answer {
        let req = self
            .client
            .post(format!("{}{path}", self.base))
            .bearer_auth(token)
            .json(&body);
        self.send(op, req).await
    }
}

/// Run `jobs` with at most `limit` in flight.
///
/// Bounded explicitly rather than by spawning everything and hoping: a harness
/// that opens 300 sockets from one process and then queues 30,000 futures behind
/// them measures its own scheduler, not the deployment. `limit` is the knob the
/// report prints, so a run's concurrency is always stated alongside its numbers.
pub async fn bounded<F, T>(limit: usize, jobs: Vec<F>) -> Vec<T>
where
    F: std::future::Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    use futures::stream::{FuturesUnordered, StreamExt};
    let limit = limit.max(1);
    let mut queue = jobs.into_iter();
    let mut inflight = FuturesUnordered::new();
    let mut out = Vec::new();
    for _ in 0..limit {
        match queue.next() {
            Some(j) => inflight.push(tokio::spawn(j)),
            None => break,
        }
    }
    while let Some(done) = inflight.next().await {
        if let Ok(v) = done {
            out.push(v);
        }
        if let Some(j) = queue.next() {
            inflight.push(tokio::spawn(j));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// Two properties at once, both of which the harness's honesty depends on:
    /// EVERY job runs (a dropped job is a request the report never knew it
    /// failed to make), and the in-flight count never exceeds the bound (a
    /// harness that ignores its own `--concurrency` reports a number produced
    /// under different conditions than the one it prints).
    #[tokio::test]
    async fn bounded_runs_every_job_and_never_exceeds_the_limit() {
        let live = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let limit = 4;
        let jobs: Vec<_> = (0..50)
            .map(|i| {
                let live = live.clone();
                let peak = peak.clone();
                async move {
                    let now = live.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(now, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(2)).await;
                    live.fetch_sub(1, Ordering::SeqCst);
                    i
                }
            })
            .collect();
        let mut out = bounded(limit, jobs).await;
        out.sort_unstable();
        assert_eq!(
            out,
            (0..50).collect::<Vec<i32>>(),
            "every job must run exactly once"
        );
        let peak = peak.load(Ordering::SeqCst);
        assert!(
            peak <= limit,
            "peak in-flight {peak} exceeded the bound {limit}"
        );
        assert!(
            peak > 1,
            "the runner did not actually parallelise (peak {peak})"
        );
    }

    #[tokio::test]
    async fn bounded_handles_an_empty_job_list_and_a_zero_limit() {
        let empty: Vec<std::pin::Pin<Box<dyn std::future::Future<Output = u8> + Send>>> = vec![];
        assert!(bounded(8, empty).await.is_empty());
        // A zero limit is clamped to 1 rather than deadlocking on an empty
        // in-flight set.
        let jobs: Vec<_> = (0..3).map(|i| async move { i }).collect();
        let mut out = bounded(0, jobs).await;
        out.sort_unstable();
        assert_eq!(out, vec![0, 1, 2]);
    }
}
