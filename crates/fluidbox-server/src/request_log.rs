//! The canonical per-request record.
//!
//! # One wide event, not two narrow ones
//!
//! Every HTTP request produces exactly one log record, emitted when its response
//! body ends, errors, or is dropped and carrying everything known about the
//! exchange: who asked, what they asked for, what they got, how long it took,
//! and — when it went wrong — a stable classification of why.
//!
//! The instinct is two records ("handling GET /x" then "GET /x → 200"). That is
//! twice the volume for strictly less information: the pair has to be correlated
//! by the reader, the first half tells you nothing you cannot infer from the
//! second, and a request that never finishes produces a dangling opener that
//! looks identical to one still in flight. The single completion record says
//! what happened; the SPAN (which exists for the whole request) is what says
//! something is happening now.
//!
//! # What this replaces
//!
//! `tower_http::TraceLayer` with a `debug_span!("http", …)`. That span was
//! **disabled at the default filter** — a span below the filter is never
//! created, and a span that is never created attaches no fields — so it
//! contributed nothing to any record while looking like request correlation was
//! in place. It also emitted no completion record at all: there was no access
//! log, no latency signal, and no way to attribute a slow endpoint.
//!
//! # Identity, and why it is not trusted
//!
//! `x-request-id` and `traceparent` are adopted from the caller when
//! well-formed, so a request that crossed a gateway keeps one id end to end.
//! Both are attacker-controlled, so both are validated for shape and bounded in
//! length before use — an unbounded client-supplied string would otherwise
//! become a field on every record the request produces, which is a cheap way to
//! inflate a log bill from outside.
//!
//! # Cardinality
//!
//! The record carries the ROUTE PATTERN (`/v1/sessions/{id}`), which is what
//! makes "which endpoint is slow" a group-by. The concrete id is on the record
//! too, as `session_id`, recorded by the handler once it knows — so both
//! questions are answerable and neither costs a high-cardinality route label.

use axum::body::{Body, Bytes, HttpBody};
use axum::extract::MatchedPath;
use axum::http::{header, HeaderName, HeaderValue, Request, Response, StatusCode};
use axum::middleware::Next;
use fluidbox_obs::field;
use fluidbox_obs::timing::Stopwatch;
use sha2::{Digest, Sha256};
use std::pin::Pin;
use std::task::{Context, Poll};
use tracing::Instrument;

/// The header this service reads an inbound id from and echoes an id back in.
pub const REQUEST_ID_HEADER: HeaderName = HeaderName::from_static("x-request-id");
const TRACEPARENT: HeaderName = HeaderName::from_static("traceparent");

/// Ceiling on an adopted `x-request-id`.
///
/// A client-supplied identifier lands on every record the request produces, so
/// its length is multiplied by the request's log volume. 128 characters is
/// generous for every real correlation id (a UUID is 36, a W3C trace id 32) and
/// small enough that abusing it is pointless.
const MAX_ADOPTED_REQUEST_ID: usize = 128;

/// `route` for a request that matched no route. A constant, not the raw path —
/// see where it is assigned.
const UNMATCHED_ROUTE: &str = "<unmatched>";

/// Ceiling on the concrete path recorded alongside the route pattern. Long
/// enough for every real path this service serves and short enough that a
/// multi-kilobyte URL from a scanner costs one field, not a line.
const MAX_LOGGED_PATH: usize = 256;

/// Adopt the caller's `x-request-id` when it is safe to, else mint one.
///
/// "Safe" means bounded and printable-ASCII: the value is echoed in a response
/// header and written into every record, so a control character or a newline in
/// it would be a header-splitting and a log-injection vector at once. (The
/// formatter escapes it regardless — this is the cheap first cut, not the only
/// one.)
fn resolve_request_id<B>(req: &Request<B>) -> String {
    let adopted = req
        .headers()
        .get(&REQUEST_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| {
            !v.is_empty()
                && v.len() <= MAX_ADOPTED_REQUEST_ID
                && v.bytes().all(|b| b.is_ascii_graphic() || b == b' ')
        });
    match adopted {
        Some(v) => v.to_string(),
        None => fluidbox_obs::span::new_request_id().to_string(),
    }
}

/// Derive a valid W3C trace id from an adopted request id. UUID request ids keep
/// the existing one-id/two-encodings relationship; arbitrary printable ids are
/// deterministically hashed to 16 bytes. Filtering "hex-looking" characters is
/// not enough: it produces short or empty ids and permits the forbidden all-zero
/// value.
fn trace_id_from_request_id(request_id: &str) -> String {
    if let Ok(id) = uuid::Uuid::parse_str(request_id) {
        if id.as_bytes().iter().any(|b| *b != 0) {
            return id.simple().to_string();
        }
    }
    let digest = Sha256::digest(request_id.as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    // Cryptographically negligible but protocol-significant: W3C forbids an
    // all-zero trace id, so enforce the invariant rather than relying on odds.
    if bytes.iter().all(|b| *b == 0) {
        bytes[15] = 1;
    }
    hex::encode(bytes)
}

/// Map an HTTP status onto the closed `error_kind` vocabulary.
///
/// `None` for a success: `error_kind` is what alerts group on, and stamping a
/// kind on a 200 would put successes in every failure panel.
fn error_kind_for(status: StatusCode) -> Option<&'static str> {
    use field::error_kind as k;
    Some(match status.as_u16() {
        401 => k::UNAUTHENTICATED,
        403 => k::FORBIDDEN,
        404 | 410 => k::NOT_FOUND,
        408 | 504 => k::TIMEOUT,
        409 => k::CONFLICT,
        // Backpressure is the system WORKING, and it must not be grouped with
        // faults — a queue shed and a null-pointer 500 need different responses.
        429 | 503 => k::CAPACITY,
        502 => k::UPSTREAM,
        400 | 405 | 411..=428 | 431 => k::INVALID,
        500 | 501 | 505..=599 => k::INTERNAL,
        _ => return None,
    })
}

/// Level policy for the completion record.
///
/// A 4xx is the caller's mistake and ordinary traffic — logging it at WARN
/// trains operators to ignore warnings, which is the expensive failure. A 5xx is
/// ours. `429`/`503` sit at WARN because they are neither: the system is
/// working as designed, but sustained backpressure is something an operator
/// should see without going looking.
macro_rules! emit_at_level {
    ($status:expr, $($arg:tt)*) => {
        match $status {
            429 | 503 => tracing::warn!($($arg)*),
            s if s >= 500 => tracing::error!($($arg)*),
            _ => tracing::info!($($arg)*),
        }
    };
}

/// Routes whose completion record is demoted to DEBUG.
///
/// Health probes and metric scrapes arrive on a fixed schedule from
/// infrastructure, carry no user intent, and would otherwise be the single
/// largest category in the log — on a Kubernetes deployment with a 10s
/// liveness probe that is 8,640 records a day per replica saying "yes, still
/// up". They are still logged (at DEBUG, and a FAILING probe is still promoted
/// by the level policy below), just not at the level a human reads.
fn is_routine_probe(route: &str) -> bool {
    matches!(route, "/v1/health" | "/v1/health/ready" | "/metrics")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ResponseState {
    Complete,
    BodyError,
    BodyDropped,
}

impl ResponseState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::BodyError => "body_error",
            Self::BodyDropped => "body_dropped",
        }
    }
}

/// Everything needed to emit the single wide request record once the response
/// body establishes the real terminal state. Owning the span here keeps its
/// late-bound caller/run fields available for the whole stream.
struct RequestCompletion {
    span: tracing::Span,
    stopwatch: Stopwatch,
    status: StatusCode,
    routine: bool,
    path: String,
    req_bytes: Option<u64>,
    user_agent: Option<String>,
}

impl RequestCompletion {
    fn finish(self, state: ResponseState, resp_bytes: u64) {
        self.span.in_scope(|| {
            let status_kind = error_kind_for(self.status);
            let kind = match state {
                ResponseState::BodyError => status_kind.or(Some(field::error_kind::INTERNAL)),
                ResponseState::Complete | ResponseState::BodyDropped => status_kind,
            };
            let duration_ms = self.stopwatch.ms_f64();
            let success = state == ResponseState::Complete
                && (self.status.is_success() || self.status.is_redirection());
            if self.routine && success {
                tracing::debug!(
                    status = self.status.as_u16(),
                    duration_ms,
                    path = %self.path,
                    resp_bytes,
                    response_state = state.as_str(),
                    "request"
                );
            } else {
                let status = self.status.as_u16();
                match state {
                    ResponseState::BodyError => tracing::error!(
                        status,
                        duration_ms,
                        path = %self.path,
                        req_bytes = self.req_bytes,
                        resp_bytes,
                        user_agent = self.user_agent.as_deref(),
                        error_kind = kind,
                        response_state = state.as_str(),
                        outcome = field::outcome::ERROR,
                        "request"
                    ),
                    ResponseState::BodyDropped => tracing::warn!(
                        status,
                        duration_ms,
                        path = %self.path,
                        req_bytes = self.req_bytes,
                        resp_bytes,
                        user_agent = self.user_agent.as_deref(),
                        error_kind = kind,
                        response_state = state.as_str(),
                        outcome = field::outcome::ERROR,
                        "request"
                    ),
                    ResponseState::Complete => emit_at_level!(
                        status,
                        status,
                        duration_ms,
                        path = %self.path,
                        req_bytes = self.req_bytes,
                        resp_bytes,
                        user_agent = self.user_agent.as_deref(),
                        error_kind = kind,
                        response_state = state.as_str(),
                        outcome = if success {
                            field::outcome::OK
                        } else {
                            field::outcome::ERROR
                        },
                        "request"
                    ),
                }
            }
        });
    }
}

/// Response-body adapter that keeps the request span alive and owns completion.
/// `poll_frame` runs the inner stream inside the span so diagnostics emitted by
/// an SSE/archive body retain request correlation too.
struct ObservedBody {
    inner: Body,
    completion: Option<RequestCompletion>,
    bytes: u64,
}

impl ObservedBody {
    fn new(inner: Body, completion: RequestCompletion) -> Self {
        let mut observed = Self {
            inner,
            completion: Some(completion),
            bytes: 0,
        };
        // Empty/HEAD-style bodies are already terminal. A server is allowed to
        // trust `is_end_stream` and never call `poll_frame`, so waiting for a
        // poll would misclassify an ordinary empty response as dropped.
        if observed.inner.is_end_stream() {
            observed.finish(ResponseState::Complete);
        }
        observed
    }

    fn finish(&mut self, state: ResponseState) {
        if let Some(completion) = self.completion.take() {
            completion.finish(state, self.bytes);
        }
    }
}

impl HttpBody for ObservedBody {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        let this = self.as_mut().get_mut();
        let span = this.completion.as_ref().map(|c| c.span.clone());
        let polled = match span {
            Some(span) => span.in_scope(|| Pin::new(&mut this.inner).poll_frame(cx)),
            None => Pin::new(&mut this.inner).poll_frame(cx),
        };
        match &polled {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    this.bytes = this.bytes.saturating_add(data.len() as u64);
                }
                // Consumers need not poll once the body reports end-of-stream.
                // Finalise on the last yielded frame as well as on a subsequent
                // `None`, covering both legal consumption styles.
                if this.inner.is_end_stream() {
                    this.finish(ResponseState::Complete);
                }
            }
            Poll::Ready(Some(Err(_))) => this.finish(ResponseState::BodyError),
            Poll::Ready(None) => this.finish(ResponseState::Complete),
            Poll::Pending => {}
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for ObservedBody {
    fn drop(&mut self) {
        self.finish(ResponseState::BodyDropped);
    }
}

/// The middleware.
///
/// `plane` distinguishes the listeners: `public` (:8787, the API and the
/// browser surface) from `internal` (:8788, reachable only by a sandbox). The
/// two have different trust models and different expected traffic, and telling
/// them apart is one filter rather than a route-prefix heuristic.
pub async fn layer(
    plane: &'static str,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response<axum::body::Body> {
    let request_id = resolve_request_id(&req);
    let trace_id = req
        .headers()
        .get(&TRACEPARENT)
        .and_then(|v| v.to_str().ok())
        .and_then(fluidbox_obs::span::trace_id_from_traceparent)
        .unwrap_or_else(|| trace_id_from_request_id(&request_id));

    let method = req.method().clone();
    // The route PATTERN when axum matched one. When it did not — a 404, a
    // scanner, a typo — `route` becomes a single constant rather than the raw
    // path: `route` is the GROUPING key, and letting unmatched traffic mint a
    // new value per URL would make "requests by endpoint" unreadable exactly
    // when something is probing the surface. The concrete path is still on the
    // record as `path`, bounded, which is what you actually want to read then.
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map(|m| m.as_str().to_string())
        .unwrap_or_else(|| UNMATCHED_ROUTE.to_string());
    // Query-free by construction (`uri().path()`), which is the standing rule
    // here: OAuth `code`/`state` and GitHub flow tokens ride query strings.
    let path: String = req.uri().path().chars().take(MAX_LOGGED_PATH).collect();
    let req_bytes = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    let user_agent = req
        .headers()
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        // Bounded for the same reason as the request id, and it is a field on
        // one record rather than all of them, so the cap can be tighter.
        .map(|v| v.chars().take(200).collect::<String>());

    let span = fluidbox_obs::span::request(plane, method.as_str(), &route, &request_id, &trace_id);

    let sw = Stopwatch::start();
    let routine = is_routine_probe(&route);
    let mut resp = next.run(req).instrument(span.clone()).await;

    let status = resp.status();

    // Echo the id so a caller can quote it in a bug report and an operator can
    // find the request without a timestamp and a guess. Infallible in practice
    // (the value is validated ASCII above), and a failure to build the header is
    // not a reason to fail the response.
    if let Ok(v) = HeaderValue::from_str(&request_id) {
        resp.headers_mut().insert(&REQUEST_ID_HEADER, v);
    }

    let completion = RequestCompletion {
        span,
        stopwatch: sw,
        status,
        routine,
        path,
        req_bytes,
        user_agent,
    };
    let (parts, body) = resp.into_parts();
    Response::from_parts(parts, Body::new(ObservedBody::new(body, completion)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;

    fn req(headers: &[(&'static str, &str)]) -> Request<Body> {
        let mut b = Request::builder().uri("/v1/sessions");
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        b.body(Body::empty()).unwrap()
    }

    /// A well-formed inbound id is adopted, so a request that crossed a gateway
    /// keeps ONE id end to end. This is the whole reason to read the header.
    #[test]
    fn a_well_formed_inbound_request_id_is_adopted() {
        let r = req(&[("x-request-id", "018f2c3d-0000-7000-8000-000000000001")]);
        assert_eq!(
            resolve_request_id(&r),
            "018f2c3d-0000-7000-8000-000000000001"
        );
    }

    /// …and a hostile one is not. The value is echoed in a response header and
    /// written to every record this request produces, so an unbounded or
    /// control-character-bearing id would be log inflation and log injection at
    /// once. Each of these must fall back to a minted id.
    ///
    /// Only shapes that can actually REACH this code are listed: see the test
    /// below for the ones the HTTP layer refuses to construct at all.
    #[test]
    fn hostile_inbound_request_ids_are_rejected_not_sanitised() {
        for bad in [
            "",
            "   ",
            &"A".repeat(MAX_ADOPTED_REQUEST_ID + 1),
            // Horizontal tab IS a legal header-value byte, so this one really
            // does arrive — and it would break the field/value framing of the
            // text log format if adopted verbatim.
            "id\twith\ttabs",
        ] {
            let r = req(&[("x-request-id", bad)]);
            let got = resolve_request_id(&r);
            assert_ne!(got, *bad, "adopted a hostile id: {bad:?}");
            // The fallback is a UUID, so it is always safe to echo.
            assert!(
                uuid::Uuid::parse_str(&got).is_ok(),
                "fallback was not a minted uuid: {got}"
            );
        }
    }

    /// The header-splitting shapes never reach [`resolve_request_id`] because
    /// `http` refuses to build a `HeaderValue` containing CR or LF in the first
    /// place. Asserted rather than assumed: it is the layer this code's own
    /// guard is defence in depth FOR, and if it ever changed, the guard above
    /// would be the only thing standing between an inbound header and a
    /// `Set-Cookie` injected into our response.
    #[test]
    fn cr_lf_bearing_ids_cannot_even_be_constructed_by_the_http_layer() {
        for bad in ["id\nx-injected: 1", "id\r\nSet-Cookie: a=b", "id\rx"] {
            assert!(
                HeaderValue::from_str(bad).is_err(),
                "http accepted a CR/LF header value: {bad:?}"
            );
        }
        // …and our own guard would reject them anyway.
        for bad in ["id\nx-injected: 1", "id\r\nSet-Cookie: a=b"] {
            assert!(
                !bad.bytes().all(|b| b.is_ascii_graphic() || b == b' '),
                "the adoption predicate must reject {bad:?}"
            );
        }
    }

    #[test]
    fn a_missing_header_mints_a_time_ordered_id() {
        let a = resolve_request_id(&req(&[]));
        let b = resolve_request_id(&req(&[]));
        assert_ne!(a, b);
        let (ua, ub) = (
            uuid::Uuid::parse_str(&a).unwrap(),
            uuid::Uuid::parse_str(&b).unwrap(),
        );
        assert_eq!(ua.get_version_num(), 7, "v7 sorts by time");
        assert!(ua <= ub, "ids from later requests sort later");
    }

    #[test]
    fn every_request_id_shape_derives_a_valid_trace_id() {
        for request_id in [
            "request-123",
            "no-hex-characters-here",
            "00000000000000000000000000000000",
            "018f2c3d-0000-7000-8000-000000000001",
        ] {
            let trace_id = trace_id_from_request_id(request_id);
            assert_eq!(trace_id.len(), 32, "{request_id} -> {trace_id}");
            assert!(
                trace_id
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "not lowercase hex: {trace_id}"
            );
            assert_ne!(trace_id, "00000000000000000000000000000000");
        }
        assert_eq!(
            trace_id_from_request_id("018f2c3d-0000-7000-8000-000000000001"),
            "018f2c3d000070008000000000000001",
            "UUID request ids retain the one-id/two-encodings relationship"
        );
        assert_eq!(
            trace_id_from_request_id("request-123"),
            trace_id_from_request_id("request-123"),
            "adopted non-UUID ids map deterministically"
        );
    }

    /// Backpressure must not be classified as a fault: a 429 and a 500 need
    /// different operator responses, and merging them makes both panels useless.
    #[test]
    fn status_classification_separates_backpressure_from_faults() {
        use field::error_kind as k;
        assert_eq!(
            error_kind_for(StatusCode::TOO_MANY_REQUESTS),
            Some(k::CAPACITY)
        );
        assert_eq!(
            error_kind_for(StatusCode::SERVICE_UNAVAILABLE),
            Some(k::CAPACITY)
        );
        assert_eq!(
            error_kind_for(StatusCode::INTERNAL_SERVER_ERROR),
            Some(k::INTERNAL)
        );
        assert_eq!(error_kind_for(StatusCode::BAD_GATEWAY), Some(k::UPSTREAM));
        assert_eq!(
            error_kind_for(StatusCode::UNAUTHORIZED),
            Some(k::UNAUTHENTICATED)
        );
        assert_eq!(error_kind_for(StatusCode::FORBIDDEN), Some(k::FORBIDDEN));
        assert_eq!(error_kind_for(StatusCode::CONFLICT), Some(k::CONFLICT));
        assert_eq!(error_kind_for(StatusCode::BAD_REQUEST), Some(k::INVALID));
    }

    /// A success carries NO `error_kind`, or every failure dashboard silently
    /// includes the successes.
    #[test]
    fn successes_carry_no_error_kind() {
        for s in [
            StatusCode::OK,
            StatusCode::CREATED,
            StatusCode::NO_CONTENT,
            StatusCode::FOUND,
            StatusCode::NOT_MODIFIED,
        ] {
            assert_eq!(error_kind_for(s), None, "{s}");
        }
    }

    /// Every kind this maps to must be one the vocabulary declares — a typo here
    /// produces a kind no alert matches and nobody notices.
    #[test]
    fn every_mapped_kind_is_in_the_closed_vocabulary() {
        for code in 100..600u16 {
            let Ok(s) = StatusCode::from_u16(code) else {
                continue;
            };
            if let Some(k) = error_kind_for(s) {
                assert!(
                    field::error_kind::ALL.contains(&k),
                    "{code} → {k}, which is not in error_kind::ALL"
                );
            }
        }
    }

    // ── End-to-end, through a real router ──────────────────────────────────
    //
    // The unit tests above cover the pure decisions. These drive an actual
    // `Router` with the actual middleware and a capturing subscriber, because
    // the parts most likely to break — whether `MatchedPath` is populated where
    // the layer sits, whether the span reaches the handler, whether the header
    // is echoed — are precisely the parts a unit test cannot see.

    fn router() -> axum::Router {
        use axum::routing::get;
        axum::Router::new()
            .route(
                "/v1/sessions/{id}",
                get(|| async {
                    // Stand in for a handler that has authenticated and knows
                    // what it is acting on.
                    fluidbox_obs::span::record_caller("user", "tenant-7", Some("user-3"));
                    fluidbox_obs::span::record_subject_run("run-42");
                    tracing::info!("handler ran");
                    "ok"
                }),
            )
            .route(
                "/v1/boom",
                get(|| async { (StatusCode::INTERNAL_SERVER_ERROR, "no") }),
            )
            .route(
                "/v1/unavailable",
                get(|| async { (StatusCode::SERVICE_UNAVAILABLE, "later") }),
            )
            .route(
                "/v1/stream",
                get(|| async {
                    let chunks = futures::stream::iter([
                        Ok::<_, std::io::Error>(Bytes::from_static(b"abc")),
                        Ok(Bytes::from_static(b"de")),
                    ]);
                    Response::new(Body::from_stream(chunks))
                }),
            )
            .route(
                "/v1/body-error",
                get(|| async {
                    let chunks = futures::stream::iter([
                        Ok(Bytes::from_static(b"abc")),
                        Err(std::io::Error::other("stream failed")),
                    ]);
                    Response::new(Body::from_stream(chunks))
                }),
            )
            .route(
                "/v1/never",
                get(|| async {
                    let chunks = futures::stream::pending::<Result<Bytes, std::io::Error>>();
                    Response::new(Body::from_stream(chunks))
                }),
            )
            .route("/v1/empty", get(|| async { StatusCode::NO_CONTENT }))
            .route("/v1/health", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn(move |req, next| {
                layer(field::plane::PUBLIC, req, next)
            }))
    }

    async fn drive(uri: &str) -> (Response<axum::body::Body>, Vec<serde_json::Value>) {
        use tower::ServiceExt;
        let w = fluidbox_obs::capture::CaptureWriter::new();
        let cfg = fluidbox_obs::LogConfig {
            format: fluidbox_obs::Format::Json,
            filter: "debug".into(),
            throttle_per_sec: 0,
            ..Default::default()
        };
        let (sub, _h) = fluidbox_obs::subscriber_with_writer(&cfg, w.clone()).unwrap();
        let guard = tracing::subscriber::set_default(sub);
        let resp = router()
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        // A request is not complete when only its headers exist. Drain the body
        // so the observer sees end-of-stream and emits the one completion record.
        let (parts, body) = resp.into_parts();
        let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
        let resp = Response::from_parts(parts, Body::from(bytes));
        drop(guard);
        let recs = w.json();
        (resp, recs)
    }

    /// The completion record carries the route PATTERN, the status, a duration,
    /// and — the part that makes it worth having — the identity the HANDLER
    /// resolved after the span had already opened.
    #[tokio::test]
    async fn the_completion_record_carries_the_route_status_and_late_bound_identity() {
        let (resp, recs) = drive("/v1/sessions/abc-123").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let done = recs
            .iter()
            .find(|r| r["msg"] == "request")
            .expect("a completion record was emitted");
        assert_eq!(
            done["route"], "/v1/sessions/{id}",
            "the PATTERN, not the path"
        );
        assert_eq!(
            done["path"], "/v1/sessions/abc-123",
            "…and the concrete path"
        );
        assert_eq!(done["status"], 200);
        assert_eq!(done["method"], "GET");
        assert_eq!(done["plane"], "public");
        assert_eq!(done["outcome"], "ok");
        assert!(done["duration_ms"].is_number());
        assert!(
            done.get("error_kind").is_none(),
            "a 200 carries no error_kind"
        );
        // Recorded by the handler, on a span opened before authentication ran.
        assert_eq!(done["principal"], "user");
        assert_eq!(done["tenant_id"], "tenant-7");
        assert_eq!(done["user_id"], "user-3");
        assert_eq!(done["session_id"], "run-42");
    }

    /// Records emitted BY THE HANDLER inherit the request's correlation ids —
    /// this is the property that lets an operator pull every line of one
    /// request out of a day's logs.
    #[tokio::test]
    async fn handler_records_inherit_the_request_correlation() {
        let (_, recs) = drive("/v1/sessions/abc-123").await;
        let handler = recs
            .iter()
            .find(|r| r["msg"] == "handler ran")
            .expect("the handler's own record");
        let done = recs.iter().find(|r| r["msg"] == "request").unwrap();
        assert_eq!(handler["request_id"], done["request_id"]);
        assert!(!handler["request_id"].as_str().unwrap().is_empty());
        assert_eq!(handler["route"], "/v1/sessions/{id}");
        assert_eq!(handler["trace_id"], done["trace_id"]);
    }

    /// A 500 is OURS: it is logged at error, classified, and marked as a
    /// failure — the three things an alert needs.
    #[tokio::test]
    async fn a_server_error_is_logged_at_error_and_classified() {
        let (resp, recs) = drive("/v1/boom").await;
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let done = recs.iter().find(|r| r["msg"] == "request").unwrap();
        assert_eq!(done["level"], "error");
        assert_eq!(done["error_kind"], "internal");
        assert_eq!(done["outcome"], "error");
    }

    #[tokio::test]
    async fn service_unavailable_is_warning_level_backpressure() {
        let (resp, recs) = drive("/v1/unavailable").await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let done = recs.iter().find(|r| r["msg"] == "request").unwrap();
        assert_eq!(done["level"], "warn");
        assert_eq!(done["error_kind"], "capacity");
    }

    #[tokio::test]
    async fn completion_waits_for_the_stream_and_counts_actual_bytes() {
        use tower::ServiceExt;
        let w = fluidbox_obs::capture::CaptureWriter::new();
        let cfg = fluidbox_obs::LogConfig {
            format: fluidbox_obs::Format::Json,
            filter: "debug".into(),
            throttle_per_sec: 0,
            ..Default::default()
        };
        let (sub, _h) = fluidbox_obs::subscriber_with_writer(&cfg, w.clone()).unwrap();
        let guard = tracing::subscriber::set_default(sub);
        let resp = router()
            .oneshot(
                Request::builder()
                    .uri("/v1/stream")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            !w.json().iter().any(|r| r["msg"] == "request"),
            "headers alone must not complete a streaming request"
        );
        let (_parts, body) = resp.into_parts();
        let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
        assert_eq!(&bytes[..], b"abcde");
        let recs = w.json();
        let done = recs.iter().find(|r| r["msg"] == "request").unwrap();
        assert_eq!(done["resp_bytes"], 5);
        assert_eq!(done["response_state"], "complete");
        drop(guard);
    }

    #[tokio::test]
    async fn already_terminal_empty_body_completes_without_a_poll() {
        let (response, records) = drive("/v1/empty").await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let completions: Vec<_> = records
            .iter()
            .filter(|record| record["msg"] == "request")
            .collect();
        assert_eq!(completions.len(), 1);
        assert_eq!(completions[0]["response_state"], "complete");
        assert_eq!(completions[0]["resp_bytes"], 0);
    }

    #[tokio::test]
    async fn body_error_and_drop_each_finalize_once() {
        use tower::ServiceExt;
        let w = fluidbox_obs::capture::CaptureWriter::new();
        let cfg = fluidbox_obs::LogConfig {
            format: fluidbox_obs::Format::Json,
            filter: "debug".into(),
            throttle_per_sec: 0,
            ..Default::default()
        };
        let (sub, _h) = fluidbox_obs::subscriber_with_writer(&cfg, w.clone()).unwrap();
        let guard = tracing::subscriber::set_default(sub);

        let errored = router()
            .oneshot(
                Request::builder()
                    .uri("/v1/body-error")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let err = axum::body::to_bytes(errored.into_body(), usize::MAX).await;
        assert!(err.is_err());

        let dropped = router()
            .oneshot(
                Request::builder()
                    .uri("/v1/never")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        drop(dropped);

        let recs = w.json();
        let request_records: Vec<_> = recs.iter().filter(|r| r["msg"] == "request").collect();
        assert_eq!(request_records.len(), 2, "one terminal record per request");
        let by_state = |state: &str| {
            request_records
                .iter()
                .find(|r| r["response_state"] == state)
                .unwrap_or_else(|| panic!("missing {state}: {request_records:?}"))
        };
        assert_eq!(by_state("body_error")["resp_bytes"], 3);
        assert_eq!(by_state("body_error")["level"], "error");
        assert_eq!(by_state("body_dropped")["resp_bytes"], 0);
        assert_eq!(by_state("body_dropped")["level"], "warn");
        drop(guard);
    }

    /// The id is echoed so a caller can quote it and an operator can find the
    /// request without a timestamp and a guess.
    #[tokio::test]
    async fn the_request_id_is_echoed_in_the_response_header() {
        let (resp, recs) = drive("/v1/sessions/x").await;
        let hdr = resp
            .headers()
            .get("x-request-id")
            .expect("x-request-id echoed")
            .to_str()
            .unwrap()
            .to_string();
        let done = recs.iter().find(|r| r["msg"] == "request").unwrap();
        assert_eq!(done["request_id"], hdr, "the header and the log agree");
    }

    /// A successful health probe stays at DEBUG. On a Kubernetes deployment
    /// with a 10s liveness probe this is thousands of records a day per replica
    /// that would otherwise be the largest single category in the log.
    #[tokio::test]
    async fn a_successful_probe_is_demoted_to_debug() {
        let (_, recs) = drive("/v1/health").await;
        let done = recs.iter().find(|r| r["msg"] == "request").unwrap();
        assert_eq!(done["level"], "debug");
        assert_eq!(done["status"], 200);
    }

    #[test]
    fn probe_routes_are_demoted_but_nothing_else_is() {
        assert!(is_routine_probe("/v1/health"));
        assert!(is_routine_probe("/v1/health/ready"));
        assert!(is_routine_probe("/metrics"));
        assert!(!is_routine_probe("/v1/sessions"));
        assert!(!is_routine_probe("/internal/sessions/{id}/permission"));
    }
}
