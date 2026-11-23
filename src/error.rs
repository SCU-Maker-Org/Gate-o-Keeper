use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorCode {
    InvalidArgument,
    Unauthorized,
    DeviceKicked,
    Forbidden,
    AdapterForbidden,
    LockForbidden,
    DevicePending,
    DeviceRevoked,
    AdapterNotFound,
    LockNotFound,
    NotFound,
    Conflict,
    AdapterBusy,
    LockUnbound,
    DeviceAlreadyRegistered,
    ReplayRejected,
    RateLimited,
    Internal,
    DeviceError,
    AdapterOffline,
    DeviceTimeout,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArgument => "INVALID_ARGUMENT",
            Self::Unauthorized => "UNAUTHORIZED",
            Self::DeviceKicked => "DEVICE_KICKED",
            Self::Forbidden => "FORBIDDEN",
            Self::AdapterForbidden => "ADAPTER_FORBIDDEN",
            Self::LockForbidden => "LOCK_FORBIDDEN",
            Self::DevicePending => "DEVICE_PENDING",
            Self::DeviceRevoked => "DEVICE_REVOKED",
            Self::AdapterNotFound => "ADAPTER_NOT_FOUND",
            Self::LockNotFound => "LOCK_NOT_FOUND",
            Self::NotFound => "NOT_FOUND",
            Self::Conflict => "CONFLICT",
            Self::AdapterBusy => "ADAPTER_BUSY",
            Self::LockUnbound => "LOCK_UNBOUND",
            Self::DeviceAlreadyRegistered => "DEVICE_ALREADY_REGISTERED",
            Self::ReplayRejected => "REPLAY_REJECTED",
            Self::RateLimited => "RATE_LIMITED",
            Self::Internal => "INTERNAL",
            Self::DeviceError => "DEVICE_ERROR",
            Self::AdapterOffline => "ADAPTER_OFFLINE",
            Self::DeviceTimeout => "DEVICE_TIMEOUT",
        }
    }

    pub fn http_status(self) -> StatusCode {
        match self {
            Self::InvalidArgument => StatusCode::BAD_REQUEST,
            Self::Unauthorized | Self::DeviceKicked => StatusCode::UNAUTHORIZED,
            Self::Forbidden
            | Self::AdapterForbidden
            | Self::LockForbidden
            | Self::DevicePending
            | Self::DeviceRevoked => StatusCode::FORBIDDEN,
            Self::AdapterNotFound | Self::LockNotFound | Self::NotFound => StatusCode::NOT_FOUND,
            Self::Conflict
            | Self::AdapterBusy
            | Self::LockUnbound
            | Self::DeviceAlreadyRegistered
            | Self::ReplayRejected => StatusCode::CONFLICT,
            Self::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            Self::Internal => StatusCode::INTERNAL_SERVER_ERROR,
            Self::DeviceError => StatusCode::BAD_GATEWAY,
            Self::AdapterOffline => StatusCode::SERVICE_UNAVAILABLE,
            Self::DeviceTimeout => StatusCode::GATEWAY_TIMEOUT,
        }
    }
}

#[derive(Debug)]
pub struct AppError {
    pub code: ErrorCode,
    pub message: String,
    pub request_id: String,
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.message)
    }
}

impl std::error::Error for AppError {}

impl AppError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            request_id: String::new(),
        }
    }

    pub fn with_request_id(mut self, request_id: impl Into<String>) -> Self {
        self.request_id = request_id.into();
        self
    }

    pub fn invalid(msg: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidArgument, msg)
    }

    pub fn unauthorized(msg: impl Into<String>) -> Self {
        Self::new(ErrorCode::Unauthorized, msg)
    }

    pub fn forbidden(msg: impl Into<String>) -> Self {
        Self::new(ErrorCode::Forbidden, msg)
    }

    pub fn not_found(msg: impl Into<String>) -> Self {
        Self::new(ErrorCode::NotFound, msg)
    }

    pub fn conflict(msg: impl Into<String>) -> Self {
        Self::new(ErrorCode::Conflict, msg)
    }

    pub fn internal(msg: impl Into<String>) -> Self {
        Self::new(ErrorCode::Internal, msg)
    }
}

impl From<sqlx::Error> for AppError {
    fn from(err: sqlx::Error) -> Self {
        tracing::error!(error = %err, "database error");
        Self::internal("database operation failed")
    }
}

impl From<redis::RedisError> for AppError {
    fn from(err: redis::RedisError) -> Self {
        tracing::error!(error = %err, "redis error");
        Self::internal("cache operation failed")
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiEnvelope<T: Serialize> {
    pub code: String,
    pub message: String,
    pub data: T,
    pub request_id: String,
}

impl<T: Serialize> ApiEnvelope<T> {
    pub fn ok(data: T, request_id: impl Into<String>) -> Json<Self> {
        Json(Self {
            code: "OK".to_string(),
            message: "success".to_string(),
            data,
            request_id: request_id.into(),
        })
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = self.code.http_status();
        let req_id = if self.request_id.is_empty() {
            format!("req_{}", uuid::Uuid::new_v4().simple())
        } else {
            self.request_id
        };
        let body = ApiEnvelope {
            code: self.code.as_str().to_string(),
            message: self.message,
            data: serde_json::Value::Null,
            request_id: req_id,
        };
        (status, Json(body)).into_response()
    }
}

pub type AppResult<T> = Result<T, AppError>;
