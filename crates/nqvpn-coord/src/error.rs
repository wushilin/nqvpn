//! Uniform API error model (DESIGN.md §3.4): JSON
//! `{ "error": { "code", "message" } }` with codes members act on.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use nqvpn_proto::api::{ErrorBody, ErrorDetail};
use nqvpn_proto::errors::ErrorCode;

#[derive(Debug, Clone)]
pub struct ApiError {
    pub status: StatusCode,
    /// From the shared vocabulary (`nqvpn_proto::errors`), so members
    /// decide what to do without parsing prose.
    pub code: ErrorCode,
    pub message: String,
}

impl ApiError {
    pub fn new(status: StatusCode, code: ErrorCode, message: impl Into<String>) -> Self {
        ApiError { status, code, message: message.into() }
    }

    pub fn bad_credentials() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, ErrorCode::BadCredentials, "unknown node id or wrong secret")
    }
    pub fn client_disabled() -> Self {
        Self::new(StatusCode::FORBIDDEN, ErrorCode::ClientDisabled, "member is administratively disabled")
    }
    pub fn prefix_conflict(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, ErrorCode::PrefixConflict, msg)
    }
    pub fn address_in_use(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, ErrorCode::AddressInUse, msg)
    }
    pub fn address_space_exhausted(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, ErrorCode::AddressSpaceExhausted, msg)
    }
    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, ErrorCode::BadRequest, msg)
    }
    pub fn rate_limited() -> Self {
        Self::new(StatusCode::TOO_MANY_REQUESTS, ErrorCode::RateLimited, "slow down")
    }
    pub fn unauthorized_admin() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, ErrorCode::AdminAuthRequired, "missing or bad admin token")
    }
    /// The advertised relay address answered nothing, and this network
    /// requires relays to be dialable (§3.2).
    pub fn relay_unreachable(addr: &str) -> Self {
        Self::new(
            StatusCode::CONFLICT,
            ErrorCode::RelayUnreachable,
            format!("nothing answered at the advertised relay_addr {addr}"),
        )
    }
    pub fn not_found(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, ErrorCode::NotFound, msg)
    }
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, ErrorCode::Internal, msg)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = ErrorBody {
            error: ErrorDetail { code: self.code.as_str().to_string(), message: self.message },
        };
        (self.status, Json(body)).into_response()
    }
}
