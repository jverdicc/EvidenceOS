use thiserror::Error;

pub type EvidenceOSResult<T> = Result<T, EvidenceOSError>;

#[derive(Debug, Error)]
pub enum EvidenceOSError {
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("budget exhausted; session frozen")]
    Frozen,

    #[error("ASPEC verification failed: {0}")]
    AspecRejected(String),

    #[error("internal error: {0}")]
    Internal(String),
}
