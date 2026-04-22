//! Error model — RFC 7807 problem+json responses.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;
use utoipa::ToSchema;

/// RFC 7807 problem+json body.
#[derive(Debug, Serialize, ToSchema)]
pub struct ProblemDetails {
    /// Short, human-readable summary of the problem type.
    pub title: String,
    /// HTTP status code for this occurrence of the problem.
    pub status: u16,
    /// Human-readable explanation specific to this occurrence.
    pub detail: String,
}

/// All error variants returned by the REST layer.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("unauthorized: {0}")]
    Unauthorized(String),
    #[error("too many requests: {0}")]
    TooManyRequests(String),
    #[error("upstream dark error: {0}")]
    Upstream(String),
    #[error("internal error: {0}")]
    Internal(String),
}

impl ApiError {
    fn status(&self) -> StatusCode {
        match self {
            ApiError::NotFound(_) => StatusCode::NOT_FOUND,
            ApiError::BadRequest(_) => StatusCode::BAD_REQUEST,
            ApiError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            ApiError::TooManyRequests(_) => StatusCode::TOO_MANY_REQUESTS,
            ApiError::Upstream(_) => StatusCode::BAD_GATEWAY,
            ApiError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn title(&self) -> &'static str {
        match self {
            ApiError::NotFound(_) => "Not Found",
            ApiError::BadRequest(_) => "Bad Request",
            ApiError::Unauthorized(_) => "Unauthorized",
            ApiError::TooManyRequests(_) => "Too Many Requests",
            ApiError::Upstream(_) => "Bad Gateway",
            ApiError::Internal(_) => "Internal Server Error",
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status();
        let body = ProblemDetails {
            title: self.title().to_string(),
            status: status.as_u16(),
            detail: self.to_string(),
        };
        let mut response = (status, Json(body)).into_response();
        response.headers_mut().insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/problem+json"),
        );
        response
    }
}

impl From<dark_client::ClientError> for ApiError {
    fn from(err: dark_client::ClientError) -> Self {
        ApiError::Upstream(err.to_string())
    }
}

pub type ApiResult<T> = Result<T, ApiError>;

/// Default 404 handler.
pub async fn route_not_found() -> ApiError {
    ApiError::NotFound("no such route".into())
}
