use tonic::{metadata::MetadataValue, Code, Status};

pub const PUBLIC_ERROR_METADATA_KEY: &str = "x-evidenceos-public-error-code";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicErrorCode {
    InvalidInput,
    Unauthorized,
    Forbidden,
    NotFound,
    FailedPrecondition,
    RateLimited,
    ResourceExhausted,
    Internal,
    Unavailable,
    DeadlineExceeded,
}

impl PublicErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidInput => "INVALID_INPUT",
            Self::Unauthorized => "UNAUTHORIZED",
            Self::Forbidden => "FORBIDDEN",
            Self::NotFound => "NOT_FOUND",
            Self::FailedPrecondition => "FAILED_PRECONDITION",
            Self::RateLimited => "RATE_LIMITED",
            Self::ResourceExhausted => "RESOURCE_EXHAUSTED",
            Self::Internal => "INTERNAL",
            Self::Unavailable => "UNAVAILABLE",
            Self::DeadlineExceeded => "DEADLINE_EXCEEDED",
        }
    }
}

pub fn public_status(grpc_code: Code, public_code: PublicErrorCode) -> Status {
    let message = match grpc_code {
        Code::InvalidArgument => "invalid request",
        Code::Unauthenticated => "authentication failed",
        Code::PermissionDenied => "permission denied",
        Code::NotFound => "resource not found",
        Code::FailedPrecondition => "operation blocked by policy",
        Code::ResourceExhausted => "resource exhausted",
        Code::DeadlineExceeded => "deadline exceeded",
        Code::Unavailable => "service unavailable",
        _ => "internal error",
    };
    let mut status = Status::new(grpc_code, message);
    status.metadata_mut().insert(
        PUBLIC_ERROR_METADATA_KEY,
        MetadataValue::from_static(public_code.as_str()),
    );
    status
}
