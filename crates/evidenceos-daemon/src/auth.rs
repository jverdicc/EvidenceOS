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

use std::time::Duration;

use prost::Message;
use sha2::{Digest, Sha256};
use tonic::metadata::MetadataMap;
use tonic::service::Interceptor;
use tonic::{GrpcMethod, Request, Status};

#[derive(Debug, Clone)]
pub enum AuthConfig {
    BearerToken(String),
    HmacKey(Vec<u8>),
}

#[derive(Debug, Clone)]
pub struct RequestGuard {
    auth: Option<AuthConfig>,
    timeout: Option<Duration>,
}

impl RequestGuard {
    pub fn new(auth: Option<AuthConfig>, timeout: Option<Duration>) -> Self {
        Self { auth, timeout }
    }

    fn validate_auth(&self, metadata: &MetadataMap) -> Result<(), Status> {
        match &self.auth {
            Some(AuthConfig::BearerToken(expected)) => {
                let Some(header) = metadata.get("authorization") else {
                    return Err(Status::unauthenticated("missing authorization"));
                };
                let Ok(header) = header.to_str() else {
                    return Err(Status::unauthenticated("invalid authorization header"));
                };
                let Some(provided) = header.strip_prefix("Bearer ") else {
                    return Err(Status::unauthenticated("invalid bearer token"));
                };
                if provided != expected {
                    return Err(Status::unauthenticated("invalid bearer token"));
                }
                Ok(())
            }
            Some(AuthConfig::HmacKey(secret)) => {
                let Some(req_id) = read_request_id(metadata) else {
                    return Err(Status::unauthenticated("missing x-request-id"));
                };
                let Some(sig_header) = metadata.get("x-evidenceos-signature") else {
                    return Err(Status::unauthenticated("missing x-evidenceos-signature"));
                };
                let Ok(sig_header) = sig_header.to_str() else {
                    return Err(Status::unauthenticated("invalid x-evidenceos-signature"));
                };
                let Some(sig_hex) = sig_header.strip_prefix("sha256=") else {
                    return Err(Status::unauthenticated("invalid signature format"));
                };
                let Ok(provided_sig) = hex::decode(sig_hex) else {
                    return Err(Status::unauthenticated("invalid signature"));
                };

                let expected = hmac_sha256(secret, req_id.as_bytes());
                if constant_time_eq(expected.as_slice(), provided_sig.as_slice()) {
                    Ok(())
                } else {
                    Err(Status::unauthenticated("invalid signature"))
                }
            }
            None => Ok(()),
        }
    }

    fn set_timeout<T>(&self, request: &mut Request<T>) {
        if let Some(timeout) = self.timeout {
            request.set_timeout(timeout);
        }
    }
}

impl Interceptor for RequestGuard {
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
        self.validate_auth(request.metadata())?;
        let method = request
            .extensions()
            .get::<GrpcMethod<'static>>()
            .map(|m| format!("/{}/{}", m.service(), m.method()))
            .unwrap_or_else(|| "unknown".to_string());
        let req_id = read_request_id(request.metadata());
        if let Some(req_id) = req_id {
            tracing::info!(request_id = %req_id, path = %method, "accepted rpc request");
        } else {
            tracing::info!(path = %method, "accepted rpc request");
        }
        self.set_timeout(&mut request);
        Ok(request)
    }
}

fn read_request_id(metadata: &MetadataMap) -> Option<&str> {
    let value = metadata.get("x-request-id")?;
    value.to_str().ok()
}

fn hmac_sha256(secret: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK_SIZE: usize = 64;
    let mut key_block = [0u8; BLOCK_SIZE];
    if secret.len() > BLOCK_SIZE {
        let digest = Sha256::digest(secret);
        key_block[..digest.len()].copy_from_slice(&digest);
    } else {
        key_block[..secret.len()].copy_from_slice(secret);
    }

    let mut o_key_pad = [0u8; BLOCK_SIZE];
    let mut i_key_pad = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        o_key_pad[i] = key_block[i] ^ 0x5c;
        i_key_pad[i] = key_block[i] ^ 0x36;
    }

    let mut inner = Sha256::new();
    inner.update(i_key_pad);
    inner.update(message);
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(o_key_pad);
    outer.update(inner_hash);
    outer.finalize().into()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub fn decode_with_max_size<T: Message + Default>(
    bytes: &[u8],
    max_bytes: usize,
) -> Result<T, Status> {
    if bytes.len() > max_bytes {
        return Err(Status::resource_exhausted("request too large"));
    }
    T::decode(bytes).map_err(|_| Status::invalid_argument("invalid protobuf payload"))
}

#[cfg(test)]
mod tests {
    use super::{AuthConfig, RequestGuard};
    use tonic::service::Interceptor;
    use tonic::{Code, Request};

    #[test]
    fn missing_token_rejected() {
        let mut guard = RequestGuard::new(
            Some(AuthConfig::BearerToken("top-secret".to_string())),
            None,
        );
        let req = Request::new(());
        let err = guard.call(req).expect_err("missing token must fail");
        assert_eq!(err.code(), Code::Unauthenticated);
    }

    #[test]
    fn wrong_token_rejected() {
        let mut guard = RequestGuard::new(
            Some(AuthConfig::BearerToken("top-secret".to_string())),
            None,
        );
        let mut req = Request::new(());
        req.metadata_mut().insert(
            "authorization",
            "Bearer wrong".parse().expect("metadata value"),
        );
        let err = guard.call(req).expect_err("wrong token must fail");
        assert_eq!(err.code(), Code::Unauthenticated);
    }

    #[test]
    fn correct_token_accepted() {
        let mut guard = RequestGuard::new(
            Some(AuthConfig::BearerToken("top-secret".to_string())),
            None,
        );
        let mut req = Request::new(());
        req.metadata_mut().insert(
            "authorization",
            "Bearer top-secret".parse().expect("metadata value"),
        );
        let accepted = guard.call(req).expect("correct token should pass");
        assert!(accepted.metadata().get("authorization").is_some());
    }

    #[test]
    fn correct_hmac_accepted() {
        let key = b"hmac-secret".to_vec();
        let mut guard = RequestGuard::new(Some(AuthConfig::HmacKey(key.clone())), None);
        let sig = hex::encode(super::hmac_sha256(&key, b"req-1"));

        let mut req = Request::new(());
        req.metadata_mut()
            .insert("x-request-id", "req-1".parse().expect("metadata value"));
        req.metadata_mut().insert(
            "x-evidenceos-signature",
            format!("sha256={sig}").parse().expect("metadata value"),
        );
        guard.call(req).expect("hmac should pass");
    }
}
