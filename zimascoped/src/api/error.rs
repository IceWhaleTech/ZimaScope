//! RFC 9457 problem details for every API failure.

use axum::{
    Json,
    http::{StatusCode, Uri, header::CONTENT_TYPE},
    response::{IntoResponse, Response},
};

use super::dto::ProblemDetails;

/// Content type required for RFC 9457 problem responses.
pub const PROBLEM_CONTENT_TYPE: &str = "application/problem+json";

/// One failure rendered as `application/problem+json`.
#[derive(Clone, Debug)]
pub struct ApiError {
    status: StatusCode,
    problem_type: &'static str,
    title: &'static str,
    detail: String,
    instance: Option<String>,
}

impl ApiError {
    pub fn bad_request(detail: impl Into<String>) -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Invalid request",
            detail,
        )
    }

    pub fn not_found(detail: impl Into<String>) -> Self {
        Self::new(
            StatusCode::NOT_FOUND,
            "not_found",
            "Resource not found",
            detail,
        )
    }

    pub fn method_not_allowed(detail: impl Into<String>) -> Self {
        Self::new(
            StatusCode::METHOD_NOT_ALLOWED,
            "method_not_allowed",
            "Method not allowed",
            detail,
        )
    }

    pub fn conflict(detail: impl Into<String>) -> Self {
        Self::new(
            StatusCode::CONFLICT,
            "conflict",
            "Request conflicts with the current state",
            detail,
        )
    }

    pub fn gone(detail: impl Into<String>) -> Self {
        Self::new(
            StatusCode::GONE,
            "gone",
            "Resource is no longer available",
            detail,
        )
    }

    pub fn precondition_failed(detail: impl Into<String>) -> Self {
        Self::new(
            StatusCode::PRECONDITION_FAILED,
            "precondition_failed",
            "Precondition failed",
            detail,
        )
    }

    pub fn precondition_required(detail: impl Into<String>) -> Self {
        Self::new(
            StatusCode::PRECONDITION_REQUIRED,
            "precondition_required",
            "Precondition required",
            detail,
        )
    }

    pub fn unprocessable(detail: impl Into<String>) -> Self {
        Self::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "unprocessable_request",
            "Request cannot be processed",
            detail,
        )
    }

    pub fn internal(detail: impl Into<String>) -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "Internal error",
            detail,
        )
    }

    pub fn with_status(status: StatusCode, detail: impl Into<String>) -> Self {
        let (problem_type, title) = match status {
            StatusCode::UNSUPPORTED_MEDIA_TYPE => {
                ("unsupported_media_type", "Unsupported media type")
            }
            StatusCode::UNPROCESSABLE_ENTITY => {
                ("unprocessable_request", "Request cannot be processed")
            }
            _ => ("invalid_request", "Invalid request"),
        };
        Self::new(status, problem_type, title, detail)
    }

    pub fn with_instance(mut self, uri: &Uri) -> Self {
        self.instance = Some(uri.path().to_owned());
        self
    }

    fn new(
        status: StatusCode,
        problem_type: &'static str,
        title: &'static str,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            status,
            problem_type,
            title,
            detail: detail.into(),
            instance: None,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = ProblemDetails {
            problem_type: format!("/problems/{}", self.problem_type),
            title: self.title,
            status: self.status.as_u16(),
            detail: self.detail,
            instance: self.instance,
        };
        (
            self.status,
            [(CONTENT_TYPE, PROBLEM_CONTENT_TYPE)],
            Json(body),
        )
            .into_response()
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.status, self.detail)
    }
}

impl std::error::Error for ApiError {}
