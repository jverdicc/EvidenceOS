// Copyright [2026] [Joseph Verdicchio]
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
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

    #[error("invalid canonical encoding")]
    InvalidCanonicalEncoding,

    #[error("NaN values are not allowed")]
    NaNNotAllowed,

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
            EvidenceOSError::InvalidCanonicalEncoding => ErrorCode::EInvalidArgument,
            EvidenceOSError::NaNNotAllowed => ErrorCode::EInvalidArgument,
            EvidenceOSError::Internal => ErrorCode::EInternal,
        }
    }
}
