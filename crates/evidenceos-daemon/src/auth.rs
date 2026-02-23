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

use std::collections::{HashMap, HashSet};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use evidenceos_auth_protocol::verify_signature;
use prost::Message;
use sha2::{Digest, Sha256};
use tonic::metadata::MetadataMap;
use tonic::service::Interceptor;
use tonic::{GrpcMethod, Request, Status};

const DEFAULT_REPLAY_TTL: Duration = Duration::from_secs(300);
const MAX_REQUEST_ID_LEN: usize = 128;
const MAX_SCOPES_HEADER_LEN: usize = 1024;
const DEFAULT_HMAC_KEY_ID: &str = "default";
const MAX_KEY_ID_LEN: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrincipalRole {
    Operator,
    Auditor,
    Agent,
}

#[derive(Debug, Clone)]
pub struct CallerIdentity {
    pub principal_id: String,
    pub role: PrincipalRole,
}

impl CallerIdentity {
    pub fn is_operator(&self) -> bool {
        self.role == PrincipalRole::Operator
    }

    pub fn is_auditor(&self) -> bool {
        self.role == PrincipalRole::Auditor
    }
}

#[derive(Debug, Clone)]
pub enum AuthConfig {
    BearerToken(String),
    BearerRoleTokens {
        agent_tokens: HashSet<String>,
        auditor_tokens: HashSet<String>,
    },
    HmacKeyring(HashMap<String, Vec<u8>>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthenticatedRole {
    Auditor,
    Agent,
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

    #[allow(clippy::result_large_err)]
    fn validate_auth(
        &self,
        metadata: &MetadataMap,
        path: &str,
    ) -> Result<AuthenticatedRole, Status> {
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
                Ok(AuthenticatedRole::Auditor)
            }
            Some(AuthConfig::BearerRoleTokens {
                agent_tokens,
                auditor_tokens,
            }) => {
                let Some(header) = metadata.get("authorization") else {
                    return Err(Status::unauthenticated("missing authorization"));
                };
                let Ok(header) = header.to_str() else {
                    return Err(Status::unauthenticated("invalid authorization header"));
                };
                let Some(provided) = header.strip_prefix("Bearer ") else {
                    return Err(Status::unauthenticated("invalid bearer token"));
                };
                if auditor_tokens.contains(provided) {
                    return Ok(AuthenticatedRole::Auditor);
                }
                if agent_tokens.contains(provided) {
                    return Ok(AuthenticatedRole::Agent);
                }
                Err(Status::unauthenticated("invalid bearer token"))
            }
            Some(AuthConfig::HmacKeyring(keys)) => {
                if path == "unknown" {
                    return Err(Status::unauthenticated("missing grpc method"));
                }
                let req_id = validate_request_id(metadata)?;
                let key_id = read_key_id(metadata)?;
                let timestamp = read_timestamp(metadata)?;
                if production_mode() && timestamp.is_none() {
                    return Err(Status::unauthenticated("missing x-evidenceos-timestamp"));
                }
                let Some(secret) = keys.get(key_id) else {
                    return Err(Status::unauthenticated("unknown x-evidenceos-key-id"));
                };

                let Some(sig_header) = metadata.get("x-evidenceos-signature") else {
                    return Err(Status::unauthenticated("missing x-evidenceos-signature"));
                };
                let Ok(sig_header) = sig_header.to_str() else {
                    return Err(Status::unauthenticated("invalid x-evidenceos-signature"));
                };

                if !verify_signature(secret, req_id, path, timestamp.as_deref(), sig_header) {
                    return Err(Status::unauthenticated("invalid signature"));
                }

                Ok(AuthenticatedRole::Agent)
            }
            None => Ok(AuthenticatedRole::Agent),
        }
    }

    fn set_timeout<T>(&self, request: &mut Request<T>) {
        if let Some(timeout) = self.timeout {
            request.set_timeout(timeout);
        }
    }
}

#[allow(clippy::result_large_err)]
fn read_key_id(metadata: &MetadataMap) -> Result<&str, Status> {
    let key_id = metadata
        .get("x-evidenceos-key-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or(DEFAULT_HMAC_KEY_ID);
    if key_id.is_empty() || key_id.len() > MAX_KEY_ID_LEN {
        return Err(Status::unauthenticated("invalid x-evidenceos-key-id"));
    }
    if key_id
        .bytes()
        .any(|b| !(0x21..=0x7e).contains(&b) || b == b':')
    {
        return Err(Status::unauthenticated("invalid x-evidenceos-key-id"));
    }
    Ok(key_id)
}

impl Interceptor for RequestGuard {
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
        let method = request
            .extensions()
            .get::<GrpcMethod<'static>>()
            .map(|m| format!("/{}/{}", m.service(), m.method()))
            .unwrap_or_else(|| "unknown".to_string());
        let role = self.validate_auth(request.metadata(), &method)?;
        request.metadata_mut().insert(
            "x-evidenceos-auth-role",
            match role {
                AuthenticatedRole::Auditor => {
                    tonic::metadata::MetadataValue::from_static("auditor")
                }
                AuthenticatedRole::Agent => tonic::metadata::MetadataValue::from_static("agent"),
            },
        );

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

fn production_mode() -> bool {
    std::env::var("EVIDENCEOS_PRODUCTION_MODE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
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
fn read_timestamp(metadata: &MetadataMap) -> Result<Option<String>, Status> {
    let Some(timestamp) = metadata.get("x-evidenceos-timestamp") else {
        return Ok(None);
    };
    let Ok(timestamp) = timestamp.to_str() else {
        return Err(Status::unauthenticated("invalid x-evidenceos-timestamp"));
    };
    if timestamp.is_empty() {
        return Err(Status::unauthenticated("invalid x-evidenceos-timestamp"));
    }
    let Ok(parsed) = timestamp.parse::<u64>() else {
        return Err(Status::unauthenticated("invalid x-evidenceos-timestamp"));
    };
    validate_timestamp_skew(parsed, DEFAULT_REPLAY_TTL)?;
    Ok(Some(timestamp.to_string()))
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

pub fn derive_caller_identity(metadata: &MetadataMap) -> CallerIdentity {
    let operator_fingerprints = operator_fingerprint_allowlist();
    if let Some(v) = metadata
        .get("x-client-cert-fp")
        .and_then(|v| v.to_str().ok())
    {
        let normalized_fp = v.trim().to_ascii_lowercase();
        let san = metadata
            .get("x-client-cert-san")
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .unwrap_or_default()
            .to_string();
        let principal_source = if san.is_empty() {
            normalized_fp.clone()
        } else {
            san.clone()
        };
        let san_operator = san.eq_ignore_ascii_case("operator")
            || san.to_ascii_lowercase().contains("role=operator");
        let fp_operator = operator_fingerprints.contains(&normalized_fp);
        return CallerIdentity {
            principal_id: format!(
                "mtls:{}",
                hex::encode(sha256_bytes(principal_source.as_bytes()))
            ),
            role: if san_operator || fp_operator {
                PrincipalRole::Operator
            } else if san.to_ascii_lowercase().contains("role=auditor") {
                PrincipalRole::Auditor
            } else {
                PrincipalRole::Agent
            },
        };
    }

    if let Some(v) = metadata.get("authorization").and_then(|v| v.to_str().ok()) {
        if let Some(token) = v.strip_prefix("Bearer ") {
            if let Some(role) = metadata
                .get("x-evidenceos-auth-role")
                .and_then(|v| v.to_str().ok())
            {
                let role = match role {
                    "operator" => PrincipalRole::Operator,
                    "auditor" => PrincipalRole::Auditor,
                    _ => PrincipalRole::Agent,
                };
                return CallerIdentity {
                    principal_id: format!("bearer:{}", hex::encode(sha256_bytes(token.as_bytes()))),
                    role,
                };
            }
            let scopes_header = metadata
                .get("x-evidenceos-token-scopes")
                .and_then(|v| v.to_str().ok())
                .filter(|v| !v.is_empty() && v.len() <= MAX_SCOPES_HEADER_LEN)
                .unwrap_or_default();
            let is_operator = scopes_header
                .split([',', ' '])
                .filter(|s| !s.is_empty())
                .any(|s| s.eq_ignore_ascii_case("operator"));
            let is_auditor = scopes_header
                .split([',', ' '])
                .filter(|s| !s.is_empty())
                .any(|s| s.eq_ignore_ascii_case("auditor"));
            return CallerIdentity {
                principal_id: format!("bearer:{}", hex::encode(sha256_bytes(token.as_bytes()))),
                role: if is_operator {
                    PrincipalRole::Operator
                } else if is_auditor {
                    PrincipalRole::Auditor
                } else {
                    PrincipalRole::Agent
                },
            };
        }
    }

    if let Some(v) = metadata
        .get("x-evidenceos-signature")
        .and_then(|v| v.to_str().ok())
    {
        return CallerIdentity {
            principal_id: format!("hmac:{}", hex::encode(sha256_bytes(v.as_bytes()))),
            role: PrincipalRole::Agent,
        };
    }

    CallerIdentity {
        principal_id: "anonymous".to_string(),
        role: PrincipalRole::Agent,
    }
}

fn operator_fingerprint_allowlist() -> std::collections::HashSet<String> {
    std::env::var("EVIDENCEOS_OPERATOR_CERT_FINGERPRINTS")
        .ok()
        .map(|raw| {
            raw.split(',')
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

fn sha256_bytes(payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(payload);
    hasher.finalize().into()
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
    use std::collections::HashMap;

    use super::{AuthConfig, RequestGuard};
    use evidenceos_auth_protocol::{sign_hex, signing_material};
    use tonic::metadata::MetadataValue;
    use tonic::service::Interceptor;
    use tonic::{Code, GrpcMethod, Request};

    fn hmac_request(
        path: (&'static str, &'static str),
        req_id: &str,
        secret: &[u8],
    ) -> Request<()> {
        hmac_request_with_key_id(path, req_id, secret, None)
    }

    fn hmac_request_with_key_id(
        path: (&'static str, &'static str),
        req_id: &str,
        secret: &[u8],
        key_id: Option<&str>,
    ) -> Request<()> {
        let mut req = Request::new(());
        req.extensions_mut().insert(GrpcMethod::new(path.0, path.1));
        req.metadata_mut().insert(
            "x-request-id",
            MetadataValue::try_from(req_id).expect("request id"),
        );
        if let Some(key_id) = key_id {
            req.metadata_mut().insert(
                "x-evidenceos-key-id",
                MetadataValue::try_from(key_id).expect("key id"),
            );
        }
        let sig = sign_hex(
            secret,
            &signing_material(req_id, &format!("/{}/{}", path.0, path.1), None),
        );
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
        let mut guard = RequestGuard::new(
            Some(AuthConfig::HmacKeyring(HashMap::from([(
                "default".to_string(),
                key.clone(),
            )]))),
            None,
        );

        let req = hmac_request(("evidenceos.v1.EvidenceOS", "Health"), "req-1", &key);
        guard.call(req).expect("hmac should pass");
    }

    #[test]
    fn path_bound_signature_rejected_on_different_path() {
        let key = b"hmac-secret".to_vec();
        let mut guard = RequestGuard::new(
            Some(AuthConfig::HmacKeyring(HashMap::from([(
                "default".to_string(),
                key.clone(),
            )]))),
            None,
        );

        let mut req = Request::new(());
        req.extensions_mut()
            .insert(GrpcMethod::new("evidenceos.v1.EvidenceOS", "CreateClaimV2"));
        req.metadata_mut()
            .insert("x-request-id", MetadataValue::from_static("req-2"));
        let sig = sign_hex(
            &key,
            &signing_material("req-2", "/evidenceos.v1.EvidenceOS/Health", None),
        );
        req.metadata_mut().insert(
            "x-evidenceos-signature",
            MetadataValue::try_from(format!("sha256={sig}")).expect("signature"),
        );

        let err = guard.call(req).expect_err("signature bound to other path");
        assert_eq!(err.code(), Code::Unauthenticated);
    }

    #[test]
    fn replayed_request_id_is_not_rejected_in_auth_layer() {
        let key = b"hmac-secret".to_vec();
        let mut guard = RequestGuard::new(
            Some(AuthConfig::HmacKeyring(HashMap::from([(
                "default".to_string(),
                key.clone(),
            )]))),
            None,
        );

        let req = hmac_request(("evidenceos.v1.EvidenceOS", "Health"), "req-replay", &key);
        guard.call(req).expect("first use accepted");

        let req = hmac_request(("evidenceos.v1.EvidenceOS", "Health"), "req-replay", &key);
        guard.call(req).expect("duplicate request-id passes auth");
    }

    #[test]
    fn bearer_operator_scope_maps_to_operator_role() {
        let mut req = Request::new(());
        req.metadata_mut().insert(
            "authorization",
            "Bearer role-token".parse().expect("metadata value"),
        );
        req.metadata_mut().insert(
            "x-evidenceos-token-scopes",
            "client,operator".parse().expect("metadata value"),
        );

        let caller = super::derive_caller_identity(req.metadata());
        assert!(caller.is_operator());
        assert!(caller.principal_id.starts_with("bearer:"));
    }

    #[test]
    fn mtls_allowlisted_fingerprint_maps_to_operator_role() {
        std::env::set_var("EVIDENCEOS_OPERATOR_CERT_FINGERPRINTS", "abc123");
        let mut req = Request::new(());
        req.metadata_mut().insert(
            "x-client-cert-fp",
            "abc123".parse().expect("metadata value"),
        );

        let caller = super::derive_caller_identity(req.metadata());
        assert!(caller.is_operator());
        assert!(caller.principal_id.starts_with("mtls:"));

        std::env::remove_var("EVIDENCEOS_OPERATOR_CERT_FINGERPRINTS");
    }

    #[test]
    fn hmac_requires_timestamp_in_production_mode() {
        std::env::set_var("EVIDENCEOS_PRODUCTION_MODE", "1");
        let key = b"hmac-secret".to_vec();
        let mut guard = RequestGuard::new(
            Some(AuthConfig::HmacKeyring(HashMap::from([(
                "default".to_string(),
                key.clone(),
            )]))),
            None,
        );
        let req = hmac_request(("evidenceos.v1.EvidenceOS", "Health"), "req-prod", &key);
        let err = guard.call(req).expect_err("timestamp required");
        assert_eq!(err.code(), Code::Unauthenticated);
        std::env::remove_var("EVIDENCEOS_PRODUCTION_MODE");
    }

    #[test]
    fn timestamp_skew_rejected() {
        let key = b"hmac-secret".to_vec();
        let mut guard = RequestGuard::new(
            Some(AuthConfig::HmacKeyring(HashMap::from([(
                "default".to_string(),
                key.clone(),
            )]))),
            None,
        );
        let mut req = Request::new(());
        req.extensions_mut()
            .insert(GrpcMethod::new("evidenceos.v1.EvidenceOS", "Health"));
        req.metadata_mut()
            .insert("x-request-id", MetadataValue::from_static("req-ts"));
        req.metadata_mut()
            .insert("x-evidenceos-timestamp", MetadataValue::from_static("1"));
        let sig = sign_hex(
            &key,
            &signing_material("req-ts", "/evidenceos.v1.EvidenceOS/Health", Some("1")),
        );
        req.metadata_mut().insert(
            "x-evidenceos-signature",
            MetadataValue::try_from(format!("sha256={sig}")).expect("signature"),
        );

        let err = guard.call(req).expect_err("stale timestamp must fail");
        assert_eq!(err.code(), Code::Unauthenticated);
    }

    #[test]
    fn non_default_hmac_key_id_accepted() {
        let default_key = b"default-secret".to_vec();
        let rotating_key = b"rotating-secret".to_vec();
        let mut guard = RequestGuard::new(
            Some(AuthConfig::HmacKeyring(HashMap::from([
                ("default".to_string(), default_key),
                ("kid-2026-01".to_string(), rotating_key.clone()),
            ]))),
            None,
        );

        let req = hmac_request_with_key_id(
            ("evidenceos.v1.EvidenceOS", "Health"),
            "req-kid",
            &rotating_key,
            Some("kid-2026-01"),
        );
        guard.call(req).expect("non-default key-id should pass");
    }

    #[test]
    fn unknown_hmac_key_id_rejected() {
        let default_key = b"default-secret".to_vec();
        let mut guard = RequestGuard::new(
            Some(AuthConfig::HmacKeyring(HashMap::from([(
                "default".to_string(),
                default_key.clone(),
            )]))),
            None,
        );

        let req = hmac_request_with_key_id(
            ("evidenceos.v1.EvidenceOS", "Health"),
            "req-unknown-kid",
            &default_key,
            Some("kid-does-not-exist"),
        );
        let err = guard.call(req).expect_err("unknown key-id must fail");
        assert_eq!(err.code(), Code::Unauthenticated);
    }
}
