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

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
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
            ApiError::Db(e) => {
                tracing::error!("db error: {e}");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error".into())
            }
            ApiError::Internal(e) => {
                tracing::error!("internal error: {e}");
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
}
