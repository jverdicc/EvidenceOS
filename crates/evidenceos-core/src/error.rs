// Copyright (c) 2026 Joseph Verdicchio and EvidenceOS Contributors
// SPDX-License-Identifier: Apache-2.0

use evidenceos_protocol::ErrorCode;
use thiserror::Error;

pub type EvidenceOSResult<T> = Result<T, EvidenceOSError>;

#[derive(Debug, Error)]
pub enum EvidenceOSError {
    #[error("invalid argument")]
    InvalidArgument,

    #[error("not found")]
    NotFound,

    #[error("system frozen")]
    Frozen,

    #[error("ASPEC verification failed")]
    AspecRejected,

    #[error("internal error")]
    Internal,
}

impl EvidenceOSError {
    pub fn code(&self) -> ErrorCode {
        match self {
            EvidenceOSError::InvalidArgument => ErrorCode::EInvalidArgument,
            EvidenceOSError::NotFound => ErrorCode::ENotFound,
            EvidenceOSError::Frozen => ErrorCode::ESystemFrozen,
            EvidenceOSError::AspecRejected => ErrorCode::EAspecRejected,
            EvidenceOSError::Internal => ErrorCode::EInternal,
        }
    }
}
