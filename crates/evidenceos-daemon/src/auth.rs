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

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;
use prost::Message;
use sha2::{Digest, Sha256};
use tonic::metadata::MetadataMap;
use tonic::service::Interceptor;
use tonic::{GrpcMethod, Request, Status};

const DEFAULT_REPLAY_TTL: Duration = Duration::from_secs(300);
const DEFAULT_MAX_REPLAY_IDS: usize = 10_000;
const MAX_REQUEST_ID_LEN: usize = 128;

#[derive(Debug, Clone)]
pub enum AuthConfig {
    BearerToken(String),
    HmacKey(Vec<u8>),
}

#[derive(Debug, Clone)]
pub struct RequestGuard {
    auth: Option<AuthConfig>,
    timeout: Option<Duration>,
    replay_cache: Arc<ReplayCache>,
}

impl RequestGuard {
    pub fn new(auth: Option<AuthConfig>, timeout: Option<Duration>) -> Self {
        Self {
            auth,
            timeout,
            replay_cache: Arc::new(ReplayCache::new(DEFAULT_REPLAY_TTL, DEFAULT_MAX_REPLAY_IDS)),
        }
    }

    #[allow(clippy::result_large_err)]
    fn validate_auth(&self, metadata: &MetadataMap, path: &str) -> Result<(), Status> {
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
                if path == "unknown" {
                    return Err(Status::unauthenticated("missing grpc method"));
                }
                let req_id = validate_request_id(metadata)?;
                let timestamp = read_timestamp(metadata)?;
                if let Some(ts) = timestamp {
                    validate_timestamp_skew(ts, DEFAULT_REPLAY_TTL)?;
                }

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

                let payload = signing_material(req_id, path, timestamp);
                let expected = hmac_sha256(secret, payload.as_bytes());
                if !constant_time_eq(expected.as_slice(), provided_sig.as_slice()) {
                    return Err(Status::unauthenticated("invalid signature"));
                }

                if !self.replay_cache.check_and_insert(req_id) {
                    return Err(Status::unauthenticated("replayed x-request-id"));
                }
                Ok(())
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
        let method = request
            .extensions()
            .get::<GrpcMethod<'static>>()
            .map(|m| format!("/{}/{}", m.service(), m.method()))
            .unwrap_or_else(|| "unknown".to_string());
        self.validate_auth(request.metadata(), &method)?;

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

#[derive(Debug)]
struct ReplayCache {
    ttl: Duration,
    max_entries: usize,
    state: Mutex<ReplayState>,
}

#[derive(Debug, Default)]
struct ReplayState {
    entries: HashMap<String, Instant>,
    order: VecDeque<(Instant, String)>,
}

impl ReplayCache {
    fn new(ttl: Duration, max_entries: usize) -> Self {
        Self {
            ttl,
            max_entries,
            state: Mutex::new(ReplayState::default()),
        }
    }

    fn check_and_insert(&self, request_id: &str) -> bool {
        let now = Instant::now();
        let mut state = self.state.lock();
        state.evict_expired(now, self.ttl);

        if state.entries.contains_key(request_id) {
            return false;
        }

        let request_id = request_id.to_owned();
        state.entries.insert(request_id.clone(), now);
        state.order.push_back((now, request_id));
        state.evict_overflow(self.max_entries);
        true
    }
}

impl ReplayState {
    fn evict_expired(&mut self, now: Instant, ttl: Duration) {
        while let Some((seen_at, request_id)) = self.order.front() {
            if now.duration_since(*seen_at) <= ttl {
                break;
            }
            let request_id = request_id.clone();
            self.order.pop_front();
            self.entries.remove(&request_id);
        }
    }

    fn evict_overflow(&mut self, max_entries: usize) {
        while self.entries.len() > max_entries {
            if let Some((_, request_id)) = self.order.pop_front() {
                self.entries.remove(&request_id);
            } else {
                break;
            }
        }
    }
}

fn signing_material(request_id: &str, path: &str, timestamp: Option<u64>) -> String {
    match timestamp {
        Some(timestamp) => format!("{request_id}:{path}:{timestamp}"),
        None => format!("{request_id}:{path}"),
    }
}

#[allow(clippy::result_large_err)]
fn validate_request_id(metadata: &MetadataMap) -> Result<&str, Status> {
    let Some(req_id) = read_request_id(metadata) else {
        return Err(Status::unauthenticated("missing x-request-id"));
    };
    if req_id.is_empty() || req_id.len() > MAX_REQUEST_ID_LEN {
        return Err(Status::unauthenticated("invalid x-request-id"));
    }
    if req_id
        .bytes()
        .any(|b| !(0x21..=0x7e).contains(&b) || b == b':')
    {
        return Err(Status::unauthenticated("invalid x-request-id"));
    }
    Ok(req_id)
}

#[allow(clippy::result_large_err)]
fn read_timestamp(metadata: &MetadataMap) -> Result<Option<u64>, Status> {
    let Some(timestamp) = metadata.get("x-evidenceos-timestamp") else {
        return Ok(None);
    };
    let Ok(timestamp) = timestamp.to_str() else {
        return Err(Status::unauthenticated("invalid x-evidenceos-timestamp"));
    };
    let Ok(timestamp) = timestamp.parse::<u64>() else {
        return Err(Status::unauthenticated("invalid x-evidenceos-timestamp"));
    };
    Ok(Some(timestamp))
}

#[allow(clippy::result_large_err)]
fn validate_timestamp_skew(timestamp: u64, max_skew: Duration) -> Result<(), Status> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Status::unauthenticated("invalid x-evidenceos-timestamp"))?
        .as_secs();
    let skew = now.abs_diff(timestamp);
    if skew > max_skew.as_secs() {
        return Err(Status::unauthenticated("timestamp skew too large"));
    }
    Ok(())
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

#[allow(clippy::result_large_err)]
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
    use super::{hmac_sha256, signing_material, AuthConfig, RequestGuard};
    use tonic::metadata::MetadataValue;
    use tonic::service::Interceptor;
    use tonic::{Code, GrpcMethod, Request};

    fn hmac_request(
        path: (&'static str, &'static str),
        req_id: &str,
        secret: &[u8],
    ) -> Request<()> {
        let mut req = Request::new(());
        req.extensions_mut().insert(GrpcMethod::new(path.0, path.1));
        req.metadata_mut().insert(
            "x-request-id",
            MetadataValue::try_from(req_id).expect("request id"),
        );
        let sig = hex::encode(hmac_sha256(
            secret,
            signing_material(req_id, &format!("/{}/{}", path.0, path.1), None).as_bytes(),
        ));
        req.metadata_mut().insert(
            "x-evidenceos-signature",
            MetadataValue::try_from(format!("sha256={sig}")).expect("signature"),
        );
        req
    }

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

        let req = hmac_request(("evidenceos.v1.EvidenceOS", "Health"), "req-1", &key);
        guard.call(req).expect("hmac should pass");
    }

    #[test]
    fn path_bound_signature_rejected_on_different_path() {
        let key = b"hmac-secret".to_vec();
        let mut guard = RequestGuard::new(Some(AuthConfig::HmacKey(key.clone())), None);

        let mut req = Request::new(());
        req.extensions_mut()
            .insert(GrpcMethod::new("evidenceos.v1.EvidenceOS", "CreateClaimV2"));
        req.metadata_mut()
            .insert("x-request-id", MetadataValue::from_static("req-2"));
        let sig = hex::encode(hmac_sha256(
            &key,
            signing_material("req-2", "/evidenceos.v1.EvidenceOS/Health", None).as_bytes(),
        ));
        req.metadata_mut().insert(
            "x-evidenceos-signature",
            MetadataValue::try_from(format!("sha256={sig}")).expect("signature"),
        );

        let err = guard.call(req).expect_err("signature bound to other path");
        assert_eq!(err.code(), Code::Unauthenticated);
    }

    #[test]
    fn replayed_request_id_rejected() {
        let key = b"hmac-secret".to_vec();
        let mut guard = RequestGuard::new(Some(AuthConfig::HmacKey(key.clone())), None);

        let req = hmac_request(("evidenceos.v1.EvidenceOS", "Health"), "req-replay", &key);
        guard.call(req).expect("first use accepted");

        let req = hmac_request(("evidenceos.v1.EvidenceOS", "Health"), "req-replay", &key);
        let err = guard.call(req).expect_err("replay must fail");
        assert_eq!(err.code(), Code::Unauthenticated);
    }

    #[test]
    fn timestamp_skew_rejected() {
        let key = b"hmac-secret".to_vec();
        let mut guard = RequestGuard::new(Some(AuthConfig::HmacKey(key.clone())), None);
        let mut req = Request::new(());
        req.extensions_mut()
            .insert(GrpcMethod::new("evidenceos.v1.EvidenceOS", "Health"));
        req.metadata_mut()
            .insert("x-request-id", MetadataValue::from_static("req-ts"));
        req.metadata_mut()
            .insert("x-evidenceos-timestamp", MetadataValue::from_static("1"));
        let sig = hex::encode(hmac_sha256(
            &key,
            signing_material("req-ts", "/evidenceos.v1.EvidenceOS/Health", Some(1)).as_bytes(),
        ));
        req.metadata_mut().insert(
            "x-evidenceos-signature",
            MetadataValue::try_from(format!("sha256={sig}")).expect("signature"),
        );

        let err = guard.call(req).expect_err("stale timestamp must fail");
        assert_eq!(err.code(), Code::Unauthenticated);
    }
}
