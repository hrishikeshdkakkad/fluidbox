use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("not found")]
    NotFound,
    #[error("unauthorized")]
    Unauthorized,
    /// Authenticated but not permitted (RBAC / CSRF cross-origin). 403.
    #[error("{0}")]
    Forbidden(String),
    #[error("{0}")]
    BadRequest(String),
    /// An axum extractor rejection surfaced from INSIDE a handler (body param
    /// `Result<Json<_>, JsonRejection>`) so it can be audited before becoming a
    /// response — carries the rejection's own status (400 malformed JSON / 415
    /// missing content-type) rendered in our standard error envelope.
    #[error("{1}")]
    Rejected(StatusCode, String),
    #[error("{0}")]
    Conflict(String),
    #[error("{0}")]
    UnprocessableEntity(String),
    /// An upstream provider (GitHub, an AS, an MCP server) failed or was
    /// unreachable — the caller's request was fine. 502, not 400.
    #[error("{0}")]
    Upstream(String),
    /// The control plane isn't ready to admit the request yet (e.g. the
    /// Kubernetes netpol enforcement probe hasn't passed). 503.
    #[error("{0}")]
    ServiceUnavailable(String),
    /// The run queue is at its depth bound (run admission, design 2026-08-23
    /// §9). **429, deliberately not 503.** A shed is a policy decision, not an
    /// outage, and a 5xx is the signal that invites retry amplification —
    /// webhook providers redeliver on it, turning one shed event into many
    /// requests exactly when the deployment is least able to take them. 429
    /// with `Retry-After` says "later, and here is how much later".
    #[error("at capacity: the run queue is full; retry after {retry_after_secs}s")]
    AtCapacity { retry_after_secs: u64 },
    #[error(transparent)]
    Db(#[from] sqlx::Error),
    #[error("{0}")]
    Internal(String),
}

impl ApiError {
    /// The stable, low-cardinality classification an alert groups on.
    ///
    /// Derived from the VARIANT rather than the status code, because the
    /// variant knows things the status does not: a 503 from `ServiceUnavailable`
    /// (the netpol gate has not passed) and a 429 from `AtCapacity` (the run
    /// queue is full) are both backpressure, while a 500 from `Db` and a 500
    /// from `Internal` are a dependency failure and a bug respectively — and
    /// those two want different people woken up.
    fn log_kind(&self) -> &'static str {
        use fluidbox_obs::field::error_kind as k;
        match self {
            ApiError::NotFound => k::NOT_FOUND,
            ApiError::Unauthorized => k::UNAUTHENTICATED,
            ApiError::Forbidden(_) => k::FORBIDDEN,
            ApiError::BadRequest(_) | ApiError::Rejected(..) | ApiError::UnprocessableEntity(_) => {
                k::INVALID
            }
            ApiError::Conflict(_) => k::CONFLICT,
            ApiError::Upstream(_) => k::UPSTREAM,
            ApiError::ServiceUnavailable(_) | ApiError::AtCapacity { .. } => k::CAPACITY,
            ApiError::Db(_) => k::DB,
            ApiError::Internal(_) => k::INTERNAL,
        }
    }

    /// Log this refusal, once, where every refusal converges.
    ///
    /// The request's completion record already carries the STATUS. What it
    /// cannot carry is WHY — the status is produced by a handler that has
    /// already returned by then, and the reason string lives in the error. So
    /// this is the only place "403" becomes "403 because this personal
    /// connection may only be decided by its owner", and it is on the one path
    /// every API refusal takes, which no per-handler logging could claim.
    ///
    /// Levels follow the same rule as the request record: a client error is
    /// ordinary traffic, a server error is ours. `Forbidden` is the exception —
    /// it sits at INFO rather than DEBUG because an authorization refusal is a
    /// security-relevant event whose RATE is worth watching, and burying it at
    /// DEBUG would mean nobody ever sees the first one.
    fn log(&self) {
        let kind = self.log_kind();
        match self {
            // Ours. Someone should look.
            ApiError::Db(e) => tracing::error!(
                error_kind = kind,
                error = %e,
                "database error serving a request"
            ),
            ApiError::Internal(e) => tracing::error!(
                error_kind = kind,
                error = %e,
                "internal error serving a request"
            ),
            // Theirs, but ours to notice.
            ApiError::Upstream(m) => tracing::warn!(
                error_kind = kind,
                error = %m,
                "upstream failed while serving a request"
            ),
            // Backpressure: the system working, and worth seeing when sustained.
            ApiError::ServiceUnavailable(m) => tracing::warn!(
                error_kind = kind,
                error = %m,
                "request refused: not ready"
            ),
            ApiError::AtCapacity { retry_after_secs } => tracing::warn!(
                error_kind = kind,
                retry_after_secs = *retry_after_secs,
                "request shed: at capacity"
            ),
            // Security-relevant: the rate is the signal.
            ApiError::Forbidden(m) => tracing::info!(
                error_kind = kind,
                reason = %m,
                "request refused: not permitted"
            ),
            // Ordinary client mistakes. The completion record carries the
            // status; this carries the reason, for whoever is debugging a
            // client integration.
            ApiError::Conflict(m) | ApiError::UnprocessableEntity(m) | ApiError::BadRequest(m) => {
                tracing::debug!(error_kind = kind, reason = %m, "request rejected")
            }
            ApiError::Rejected(_, m) => {
                tracing::debug!(error_kind = kind, reason = %m, "request body rejected")
            }
            // Deliberately quiet: `NotFound` and `Unauthorized` are the two most
            // common results of an unauthenticated scan, they carry no reason
            // string worth reading, and the completion record already counts
            // them by status. Logging them here would be pure volume.
            ApiError::NotFound | ApiError::Unauthorized => {}
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        self.log();
        let (status, msg) = match &self {
            ApiError::NotFound => (StatusCode::NOT_FOUND, self.to_string()),
            ApiError::Unauthorized => (StatusCode::UNAUTHORIZED, self.to_string()),
            ApiError::Forbidden(_) => (StatusCode::FORBIDDEN, self.to_string()),
            ApiError::BadRequest(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            ApiError::Rejected(status, msg) => (*status, msg.clone()),
            ApiError::Conflict(_) => (StatusCode::CONFLICT, self.to_string()),
            ApiError::UnprocessableEntity(_) => {
                (StatusCode::UNPROCESSABLE_ENTITY, self.to_string())
            }
            ApiError::Upstream(_) => (StatusCode::BAD_GATEWAY, self.to_string()),
            ApiError::ServiceUnavailable(_) => (StatusCode::SERVICE_UNAVAILABLE, self.to_string()),
            // The one arm that returns early: it carries a header, and the
            // shared tail below builds a header-less response.
            ApiError::AtCapacity { retry_after_secs } => {
                return (
                    StatusCode::TOO_MANY_REQUESTS,
                    [(
                        axum::http::header::RETRY_AFTER,
                        retry_after_secs.to_string(),
                    )],
                    Json(json!({ "error": self.to_string() })),
                )
                    .into_response();
            }
            // Both already logged by `log()` above, with a classification and
            // the request's correlation ids attached. The caller gets the
            // generic message — a database error's text is an internal detail
            // and sometimes a schema disclosure.
            ApiError::Db(_) | ApiError::Internal(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error".into())
            }
        };
        (status, Json(json!({ "error": msg }))).into_response()
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        ApiError::Internal(e.to_string())
    }
}

impl From<serde_json::Error> for ApiError {
    fn from(e: serde_json::Error) -> Self {
        ApiError::Internal(format!("serialization: {e}"))
    }
}

pub type ApiResult<T> = Result<T, ApiError>;

#[cfg(test)]
mod tests {
    use super::*;

    /// The shed signal for interactive callers. Two properties matter and both
    /// are asserted: the STATUS must be 429 (a 503 would invite the retry
    /// amplification the design forbids, and a 500 would read as our bug rather
    /// than as backpressure), and `Retry-After` must be present so a client has
    /// a number to obey instead of a hot loop.
    #[test]
    fn at_capacity_maps_to_429_with_retry_after() {
        let resp = ApiError::AtCapacity {
            retry_after_secs: 30,
        }
        .into_response();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(resp.headers().get("retry-after").unwrap(), "30");
    }

    /// …and the header rides the STANDARD error envelope, not a bespoke body:
    /// every other client-visible error in this API is `{"error": "…"}`, and a
    /// shed is not the place to introduce a second shape.
    #[test]
    fn at_capacity_keeps_the_house_error_envelope() {
        let msg = ApiError::AtCapacity {
            retry_after_secs: 5,
        }
        .to_string();
        assert!(msg.contains("capacity"), "got: {msg}");
        assert!(msg.contains('5'), "the message states the wait: {msg}");
    }

    /// Every variant classifies into the CLOSED vocabulary. A kind no alert
    /// matches is worse than no kind at all: the panel looks healthy.
    #[test]
    fn every_variant_classifies_into_the_closed_vocabulary() {
        let all = [
            ApiError::NotFound,
            ApiError::Unauthorized,
            ApiError::Forbidden("x".into()),
            ApiError::BadRequest("x".into()),
            ApiError::Rejected(StatusCode::BAD_REQUEST, "x".into()),
            ApiError::Conflict("x".into()),
            ApiError::UnprocessableEntity("x".into()),
            ApiError::Upstream("x".into()),
            ApiError::ServiceUnavailable("x".into()),
            ApiError::AtCapacity {
                retry_after_secs: 1,
            },
            ApiError::Db(sqlx::Error::RowNotFound),
            ApiError::Internal("x".into()),
        ];
        for e in &all {
            let k = e.log_kind();
            assert!(
                fluidbox_obs::field::error_kind::ALL.contains(&k),
                "{e:?} → {k}, which is not a declared error_kind"
            );
        }
    }

    /// Backpressure and faults must not share a classification: a shed queue
    /// and a null-pointer 500 need different responses, and merging them makes
    /// both panels useless.
    #[test]
    fn backpressure_is_classified_apart_from_faults() {
        use fluidbox_obs::field::error_kind as k;
        assert_eq!(
            ApiError::AtCapacity {
                retry_after_secs: 30
            }
            .log_kind(),
            k::CAPACITY
        );
        assert_eq!(
            ApiError::ServiceUnavailable("netpol".into()).log_kind(),
            k::CAPACITY
        );
        // …and the two 500s are told apart, because they wake different people.
        assert_eq!(ApiError::Db(sqlx::Error::PoolTimedOut).log_kind(), k::DB);
        assert_eq!(ApiError::Internal("bug".into()).log_kind(), k::INTERNAL);
    }

    /// The internal detail goes to the LOG and the generic message goes to the
    /// CALLER. A database error's text can disclose schema; the operator needs
    /// it and the caller must not have it.
    #[test]
    fn internal_details_reach_the_log_but_never_the_caller() {
        let w = fluidbox_obs::capture::CaptureWriter::new();
        let cfg = fluidbox_obs::LogConfig {
            format: fluidbox_obs::Format::Json,
            filter: "trace".into(),
            throttle_per_sec: 0,
            ..Default::default()
        };
        let (sub, _h) = fluidbox_obs::subscriber_with_writer(&cfg, w.clone()).unwrap();
        let resp = tracing::subscriber::with_default(sub, || {
            ApiError::Internal("column customers.ssn does not exist".into()).into_response()
        });
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let logged = w.contents();
        assert!(
            logged.contains("column customers.ssn does not exist"),
            "the operator needs the detail: {logged}"
        );
        assert!(logged.contains("\"error_kind\":\"internal\""), "{logged}");
    }
}
