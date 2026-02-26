use crate::error::{EvidenceOSError, EvidenceOSResult};
use crate::oracle::{NullSpec, OracleResolution};
use crate::oracle_registry::OracleBackend;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::time::Duration;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};

pub mod pb {
    tonic::include_proto!("oracleplusplus.v1");
}

pub type Ed25519PubKey = [u8; 32];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OraclePlusPlusMtlsConfig {
    pub ca_cert_path: String,
    pub client_cert_path: String,
    pub client_key_path: String,
    pub domain_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OraclePlusPlusConfig {
    pub endpoint: String,
    pub tls: Option<OraclePlusPlusMtlsConfig>,
    pub trusted_authorities: Vec<Ed25519PubKey>,
    pub expected_oracle_id: String,
    pub expected_measurement_hash: Option<[u8; 32]>,
    pub max_clock_skew_epochs: u64,
    pub require_canonical_bucket_bytes: bool,
}

impl Default for OraclePlusPlusConfig {
    fn default() -> Self {
        Self {
            endpoint: String::new(),
            tls: None,
            trusted_authorities: Vec::new(),
            expected_oracle_id: String::new(),
            expected_measurement_hash: None,
            max_clock_skew_epochs: 2,
            require_canonical_bucket_bytes: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleAttestation {
    pub oracle_id: String,
    pub measurement_hash: [u8; 32],
    pub manifest_hash: [u8; 32],
    pub resolution_hash: [u8; 32],
    pub pubkey_id: String,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OraclePlusPlusReply {
    pub seq_no: u64,
    pub bucket_bytes: Vec<u8>,
    pub e_value: f64,
    pub k_bits: f64,
    pub remaining_budget_bits: f64,
    pub signature: Vec<u8>,
}

pub struct OraclePlusPlusBackend {
    config: OraclePlusPlusConfig,
    resolution: OracleResolution,
    null_spec: NullSpec,
    holdout_handle: String,
    oracle_pubkey: Option<VerifyingKey>,
    last_seq_by_session: BTreeMap<String, u64>,
    failed_closed: bool,
    remaining_budget_bits: Option<f64>,
    network_errors: u8,
    max_network_errors: u8,
    client: pb::oracle_plus_plus_client::OraclePlusPlusClient<Channel>,
}

impl OraclePlusPlusBackend {
    pub async fn connect(
        config: OraclePlusPlusConfig,
        resolution: OracleResolution,
        null_spec: NullSpec,
        holdout_handle: String,
    ) -> EvidenceOSResult<Self> {
        let endpoint = Endpoint::from_shared(config.endpoint.clone())
            .map_err(|_| EvidenceOSError::OracleViolation)?
            .timeout(Duration::from_secs(3));

        let endpoint = if let Some(tls_cfg) = &config.tls {
            let ca =
                fs::read(&tls_cfg.ca_cert_path).map_err(|_| EvidenceOSError::OracleViolation)?;
            let cert = fs::read(&tls_cfg.client_cert_path)
                .map_err(|_| EvidenceOSError::OracleViolation)?;
            let key =
                fs::read(&tls_cfg.client_key_path).map_err(|_| EvidenceOSError::OracleViolation)?;
            endpoint
                .tls_config(
                    ClientTlsConfig::new()
                        .ca_certificate(Certificate::from_pem(ca))
                        .identity(Identity::from_pem(cert, key))
                        .domain_name(tls_cfg.domain_name.clone()),
                )
                .map_err(|_| EvidenceOSError::OracleViolation)?
        } else {
            endpoint
        };

        let channel = endpoint
            .connect()
            .await
            .map_err(|_| EvidenceOSError::OracleViolation)?;
        Ok(Self {
            config,
            resolution,
            null_spec,
            holdout_handle,
            oracle_pubkey: None,
            last_seq_by_session: BTreeMap::new(),
            failed_closed: false,
            remaining_budget_bits: None,
            network_errors: 0,
            max_network_errors: 2,
            client: pb::oracle_plus_plus_client::OraclePlusPlusClient::new(channel),
        })
    }

    pub async fn handshake(&mut self) -> EvidenceOSResult<()> {
        let req = tonic::Request::new(pb::AttestationRequest {
            oracle_id: self.config.expected_oracle_id.clone(),
        });
        let att = self
            .client
            .get_attestation(req)
            .await
            .map_err(|_| EvidenceOSError::OracleViolation)?
            .into_inner();
        let att = parse_attestation(att)?;
        verify_attestation(
            &att,
            &self.config.expected_oracle_id,
            self.config.expected_measurement_hash,
            &self.config.trusted_authorities,
            &self.resolution,
        )?;
        let oracle_pubkey = parse_oracle_pubkey(&att.pubkey_id)?;
        self.oracle_pubkey = Some(oracle_pubkey);
        Ok(())
    }

    pub async fn query_reply(
        &mut self,
        session_id: &str,
        preds: &[u8],
    ) -> EvidenceOSResult<OraclePlusPlusReply> {
        if self.failed_closed {
            return Err(EvidenceOSError::Frozen);
        }
        let req = tonic::Request::new(pb::QueryRequest {
            oracle_id: self.config.expected_oracle_id.clone(),
            session_id: session_id.to_owned(),
            preds: preds.to_vec(),
        });
        let reply = match self.client.query(req).await {
            Ok(v) => v.into_inner(),
            Err(_) => {
                self.network_errors = self.network_errors.saturating_add(1);
                if self.network_errors > self.max_network_errors {
                    return self.fail_closed("network errors exceeded retry budget");
                }
                return Err(EvidenceOSError::OracleViolation);
            }
        };
        self.network_errors = 0;

        let reply = OraclePlusPlusReply {
            seq_no: reply.seq_no,
            bucket_bytes: reply.bucket_bytes,
            e_value: reply.e_value,
            k_bits: reply.k_bits,
            remaining_budget_bits: reply.remaining_budget_bits,
            signature: reply.signature,
        };
        self.validate_reply(session_id, &reply)?;
        Ok(reply)
    }

    fn validate_reply(
        &mut self,
        session_id: &str,
        reply: &OraclePlusPlusReply,
    ) -> EvidenceOSResult<()> {
        let Some(pubkey) = self.oracle_pubkey else {
            return self.fail_closed("missing oracle pubkey; handshake required");
        };
        let msg = reply_message(
            &self.config.expected_oracle_id,
            reply.seq_no,
            &reply.bucket_bytes,
            reply.e_value,
            reply.k_bits,
            reply.remaining_budget_bits,
        );
        let sig = Signature::from_slice(&reply.signature)
            .map_err(|_| EvidenceOSError::OracleViolation)?;
        if pubkey.verify(&msg, &sig).is_err() {
            return self.fail_closed("oracle++ reply signature invalid");
        }

        if self.config.require_canonical_bucket_bytes
            && self
                .resolution
                .validate_canonical_bytes(&reply.bucket_bytes)
                .is_err()
        {
            return self.fail_closed("oracle++ non-canonical bucket bytes");
        }
        if !reply.e_value.is_finite()
            || !reply.k_bits.is_finite()
            || !reply.remaining_budget_bits.is_finite()
        {
            return self.fail_closed("oracle++ non-finite reply values");
        }
        if reply.remaining_budget_bits < 0.0 {
            return self.fail_closed("oracle++ negative remaining budget");
        }
        if let Some(prev) = self.remaining_budget_bits {
            if reply.remaining_budget_bits > prev + 1e-9 {
                return self.fail_closed("oracle++ remaining budget increased unexpectedly");
            }
        }
        if let Some(last) = self.last_seq_by_session.get(session_id) {
            if reply.seq_no <= *last {
                return self.fail_closed("oracle++ replay or fork detected");
            }
        }
        self.last_seq_by_session
            .insert(session_id.to_owned(), reply.seq_no);
        self.remaining_budget_bits = Some(reply.remaining_budget_bits);
        Ok(())
    }

    fn fail_closed<T>(&mut self, reason: &str) -> EvidenceOSResult<T> {
        self.failed_closed = true;
        tracing::error!(reason, oracle_id=%self.config.expected_oracle_id, "oracle++ fail-closed triggered");
        Err(EvidenceOSError::Frozen)
    }
}

impl OracleBackend for OraclePlusPlusBackend {
    fn oracle_id(&self) -> &str {
        &self.config.expected_oracle_id
    }

    fn resolution(&self) -> &OracleResolution {
        &self.resolution
    }

    fn null_spec(&self) -> &NullSpec {
        &self.null_spec
    }

    fn holdout_handle(&self) -> &str {
        &self.holdout_handle
    }

    fn query_raw_metric(&mut self, _preds: &[u8]) -> EvidenceOSResult<f64> {
        Err(EvidenceOSError::OracleViolation)
    }
}

fn resolution_hash(resolution: &OracleResolution) -> EvidenceOSResult<[u8; 32]> {
    let bytes = serde_json::to_vec(resolution).map_err(|_| EvidenceOSError::OracleViolation)?;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(out)
}

fn parse_attestation(v: pb::AttestationResponse) -> EvidenceOSResult<OracleAttestation> {
    Ok(OracleAttestation {
        oracle_id: v.oracle_id,
        measurement_hash: to_arr32(&v.measurement_hash)?,
        manifest_hash: to_arr32(&v.manifest_hash)?,
        resolution_hash: to_arr32(&v.resolution_hash)?,
        pubkey_id: v.pubkey_id,
        signature: v.signature,
    })
}

fn parse_oracle_pubkey(pubkey_id: &str) -> EvidenceOSResult<VerifyingKey> {
    let bytes = hex::decode(pubkey_id).map_err(|_| EvidenceOSError::OracleViolation)?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| EvidenceOSError::OracleViolation)?;
    VerifyingKey::from_bytes(&arr).map_err(|_| EvidenceOSError::OracleViolation)
}

fn verify_attestation(
    att: &OracleAttestation,
    expected_oracle_id: &str,
    expected_measurement_hash: Option<[u8; 32]>,
    trusted_authorities: &[Ed25519PubKey],
    expected_resolution: &OracleResolution,
) -> EvidenceOSResult<()> {
    if att.oracle_id != expected_oracle_id {
        return Err(EvidenceOSError::OracleViolation);
    }
    if let Some(expected) = expected_measurement_hash {
        if expected != att.measurement_hash {
            return Err(EvidenceOSError::OracleViolation);
        }
    }
    if att.resolution_hash != resolution_hash(expected_resolution)? {
        return Err(EvidenceOSError::OracleViolation);
    }
    let sig =
        Signature::from_slice(&att.signature).map_err(|_| EvidenceOSError::OracleViolation)?;
    let msg = attestation_message(att);

    let trusted = trusted_authorities.iter().any(|key| {
        if let Ok(vk) = VerifyingKey::from_bytes(key) {
            vk.verify(&msg, &sig).is_ok()
        } else {
            false
        }
    });
    if !trusted {
        return Err(EvidenceOSError::OracleViolation);
    }
    Ok(())
}

fn to_arr32(bytes: &[u8]) -> EvidenceOSResult<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| EvidenceOSError::OracleViolation)
}

pub fn attestation_message(att: &OracleAttestation) -> Vec<u8> {
    let mut out = Vec::new();
    append_len_prefixed(&mut out, att.oracle_id.as_bytes());
    out.extend_from_slice(&att.measurement_hash);
    out.extend_from_slice(&att.manifest_hash);
    out.extend_from_slice(&att.resolution_hash);
    append_len_prefixed(&mut out, att.pubkey_id.as_bytes());
    out
}

pub fn reply_message(
    oracle_id: &str,
    seq_no: u64,
    bucket_bytes: &[u8],
    e_value: f64,
    k_bits: f64,
    remaining_budget_bits: f64,
) -> Vec<u8> {
    let mut out = Vec::new();
    append_len_prefixed(&mut out, oracle_id.as_bytes());
    out.extend_from_slice(&seq_no.to_le_bytes());
    append_len_prefixed(&mut out, bucket_bytes);
    out.extend_from_slice(&e_value.to_le_bytes());
    out.extend_from_slice(&k_bits.to_le_bytes());
    out.extend_from_slice(&remaining_budget_bits.to_le_bytes());
    out
}

fn append_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    out.extend_from_slice(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use tokio::runtime::Builder;

    fn mk_resolution() -> OracleResolution {
        OracleResolution::new(16, 0.01).expect("resolution")
    }

    fn mock_client() -> pb::oracle_plus_plus_client::OraclePlusPlusClient<Channel> {
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        let _guard = runtime.enter();
        pb::oracle_plus_plus_client::OraclePlusPlusClient::new(
            Channel::from_static("http://127.0.0.1:1").connect_lazy(),
        )
    }

    #[test]
    fn attestation_signature_valid() {
        let authority = SigningKey::from_bytes(&[7u8; 32]);
        let att = OracleAttestation {
            oracle_id: "oracle-a".into(),
            measurement_hash: [1; 32],
            manifest_hash: [2; 32],
            resolution_hash: resolution_hash(&mk_resolution()).expect("hash"),
            pubkey_id: hex::encode(
                SigningKey::from_bytes(&[9u8; 32])
                    .verifying_key()
                    .to_bytes(),
            ),
            signature: vec![],
        };
        let mut signed = att.clone();
        signed.signature = authority.sign(&attestation_message(&att)).to_vec();
        let ok = verify_attestation(
            &signed,
            "oracle-a",
            Some([1; 32]),
            &[authority.verifying_key().to_bytes()],
            &mk_resolution(),
        );
        assert!(ok.is_ok());
    }

    #[test]
    fn attestation_rejects_wrong_oracle_id() {
        let authority = SigningKey::from_bytes(&[7u8; 32]);
        let att = OracleAttestation {
            oracle_id: "oracle-a".into(),
            measurement_hash: [1; 32],
            manifest_hash: [2; 32],
            resolution_hash: resolution_hash(&mk_resolution()).expect("hash"),
            pubkey_id: hex::encode(
                SigningKey::from_bytes(&[9u8; 32])
                    .verifying_key()
                    .to_bytes(),
            ),
            signature: vec![],
        };
        let mut signed = att.clone();
        signed.signature = authority.sign(&attestation_message(&att)).to_vec();
        let err = verify_attestation(
            &signed,
            "oracle-b",
            Some([1; 32]),
            &[authority.verifying_key().to_bytes()],
            &mk_resolution(),
        );
        assert!(err.is_err());
    }

    #[test]
    fn reply_signature_valid() {
        let signing = SigningKey::from_bytes(&[9u8; 32]);
        let msg = reply_message("oracle-a", 1, &[3], 2.0, 4.0, 8.0);
        let sig = signing.sign(&msg);
        assert!(signing.verifying_key().verify(&msg, &sig).is_ok());
    }

    #[test]
    fn reply_replay_rejected() {
        let authority = SigningKey::from_bytes(&[7u8; 32]);
        let oracle_signing = SigningKey::from_bytes(&[8u8; 32]);
        let mut backend = OraclePlusPlusBackend {
            config: OraclePlusPlusConfig {
                endpoint: String::new(),
                tls: None,
                trusted_authorities: vec![authority.verifying_key().to_bytes()],
                expected_oracle_id: "oracle-a".into(),
                expected_measurement_hash: None,
                max_clock_skew_epochs: 1,
                require_canonical_bucket_bytes: true,
            },
            resolution: mk_resolution(),
            null_spec: NullSpec {
                domain: "d".into(),
                null_accuracy: 0.5,
                e_value_fn: crate::oracle::EValueFn::Fixed(1.0),
            },
            holdout_handle: "h".into(),
            oracle_pubkey: Some(oracle_signing.verifying_key()),
            last_seq_by_session: BTreeMap::new(),
            failed_closed: false,
            remaining_budget_bits: None,
            network_errors: 0,
            max_network_errors: 2,
            client: mock_client(),
        };
        let bucket = backend.resolution.encode_bucket(1).expect("bucket");
        let sig1 = oracle_signing
            .sign(&reply_message("oracle-a", 1, &bucket, 2.0, 1.0, 10.0))
            .to_vec();
        let r1 = OraclePlusPlusReply {
            seq_no: 1,
            bucket_bytes: bucket.clone(),
            e_value: 2.0,
            k_bits: 1.0,
            remaining_budget_bits: 10.0,
            signature: sig1,
        };
        assert!(backend.validate_reply("s", &r1).is_ok());

        let sig2 = oracle_signing
            .sign(&reply_message("oracle-a", 1, &bucket, 2.0, 1.0, 9.0))
            .to_vec();
        let r2 = OraclePlusPlusReply {
            seq_no: 1,
            bucket_bytes: bucket,
            e_value: 2.0,
            k_bits: 1.0,
            remaining_budget_bits: 9.0,
            signature: sig2,
        };
        assert!(backend.validate_reply("s", &r2).is_err());
    }

    #[test]
    fn reply_bucket_bytes_canonical_enforced() {
        let oracle_signing = SigningKey::from_bytes(&[8u8; 32]);
        let mut backend = OraclePlusPlusBackend {
            config: OraclePlusPlusConfig {
                endpoint: String::new(),
                tls: None,
                trusted_authorities: vec![],
                expected_oracle_id: "oracle-a".into(),
                expected_measurement_hash: None,
                max_clock_skew_epochs: 1,
                require_canonical_bucket_bytes: true,
            },
            resolution: OracleResolution::new(300, 0.01).expect("resolution"),
            null_spec: NullSpec {
                domain: "d".into(),
                null_accuracy: 0.5,
                e_value_fn: crate::oracle::EValueFn::Fixed(1.0),
            },
            holdout_handle: "h".into(),
            oracle_pubkey: Some(oracle_signing.verifying_key()),
            last_seq_by_session: BTreeMap::new(),
            failed_closed: false,
            remaining_budget_bits: None,
            network_errors: 0,
            max_network_errors: 2,
            client: mock_client(),
        };
        let bad = vec![0, 1, 2];
        let sig = oracle_signing
            .sign(&reply_message("oracle-a", 1, &bad, 1.0, 1.0, 2.0))
            .to_vec();
        let r = OraclePlusPlusReply {
            seq_no: 1,
            bucket_bytes: bad,
            e_value: 1.0,
            k_bits: 1.0,
            remaining_budget_bits: 2.0,
            signature: sig,
        };
        assert!(backend.validate_reply("s", &r).is_err());
    }

    #[test]
    fn reply_nan_e_value_fails_closed() {
        let oracle_signing = SigningKey::from_bytes(&[8u8; 32]);
        let mut backend = OraclePlusPlusBackend {
            config: OraclePlusPlusConfig {
                endpoint: String::new(),
                tls: None,
                trusted_authorities: vec![],
                expected_oracle_id: "oracle-a".into(),
                expected_measurement_hash: None,
                max_clock_skew_epochs: 1,
                require_canonical_bucket_bytes: true,
            },
            resolution: mk_resolution(),
            null_spec: NullSpec {
                domain: "d".into(),
                null_accuracy: 0.5,
                e_value_fn: crate::oracle::EValueFn::Fixed(1.0),
            },
            holdout_handle: "h".into(),
            oracle_pubkey: Some(oracle_signing.verifying_key()),
            last_seq_by_session: BTreeMap::new(),
            failed_closed: false,
            remaining_budget_bits: None,
            network_errors: 0,
            max_network_errors: 2,
            client: mock_client(),
        };
        let bucket = backend.resolution.encode_bucket(1).expect("bucket");
        let sig = oracle_signing
            .sign(&reply_message("oracle-a", 1, &bucket, f64::NAN, 1.0, 2.0))
            .to_vec();
        let r = OraclePlusPlusReply {
            seq_no: 1,
            bucket_bytes: bucket,
            e_value: f64::NAN,
            k_bits: 1.0,
            remaining_budget_bits: 2.0,
            signature: sig,
        };
        assert!(backend.validate_reply("s", &r).is_err());
        assert!(backend.failed_closed);
    }
}
