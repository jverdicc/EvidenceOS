use ed25519_dalek::{Signer, SigningKey};
use evidenceos_core::oracle::{EValueFn, NullSpec, OracleResolution};
use evidenceos_core::oracle_plusplus::pb::oracle_plus_plus_server::{
    OraclePlusPlus, OraclePlusPlusServer,
};
use evidenceos_core::oracle_plusplus::pb::{
    AttestationRequest, AttestationResponse, QueryRequest, QueryResponse,
};
use evidenceos_core::oracle_plusplus::{
    attestation_message, reply_message, OracleAttestation, OraclePlusPlusBackend,
    OraclePlusPlusConfig,
};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Server;
use tonic::{Request, Response, Status};

#[derive(Clone)]
struct TestOracleSvc {
    authority: SigningKey,
    oracle: SigningKey,
    resolution_hash: [u8; 32],
    state: Arc<Mutex<State>>,
}

#[derive(Default)]
struct State {
    seq_no: u64,
    tamper_bucket: bool,
    tamper_signature: bool,
    replay: bool,
}

#[tonic::async_trait]
impl OraclePlusPlus for TestOracleSvc {
    async fn get_attestation(
        &self,
        request: Request<AttestationRequest>,
    ) -> Result<Response<AttestationResponse>, Status> {
        let oracle_id = request.into_inner().oracle_id;
        let mut att = OracleAttestation {
            oracle_id,
            measurement_hash: [1; 32],
            manifest_hash: [2; 32],
            resolution_hash: self.resolution_hash,
            pubkey_id: hex::encode(self.oracle.verifying_key().to_bytes()),
            signature: vec![],
        };
        att.signature = self.authority.sign(&attestation_message(&att)).to_vec();
        Ok(Response::new(AttestationResponse {
            oracle_id: att.oracle_id,
            measurement_hash: att.measurement_hash.to_vec(),
            manifest_hash: att.manifest_hash.to_vec(),
            resolution_hash: att.resolution_hash.to_vec(),
            pubkey_id: att.pubkey_id,
            signature: att.signature,
        }))
    }

    async fn query(
        &self,
        request: Request<QueryRequest>,
    ) -> Result<Response<QueryResponse>, Status> {
        let req = request.into_inner();
        let mut state = self.state.lock().await;
        if !state.replay {
            state.seq_no += 1;
        } else if state.seq_no == 0 {
            state.seq_no = 1;
        }
        let seq_no = state.seq_no;
        let mut bucket_bytes = vec![0x01];
        if state.tamper_bucket {
            bucket_bytes = vec![0x00, 0x01];
        }
        let mut signature = self
            .oracle
            .sign(&reply_message(
                &req.oracle_id,
                seq_no,
                &bucket_bytes,
                1.25,
                1.0,
                20.0 - (seq_no as f64),
            ))
            .to_vec();
        if state.tamper_signature {
            signature[0] ^= 0xFF;
        }
        Ok(Response::new(QueryResponse {
            seq_no,
            bucket_bytes,
            e_value: 1.25,
            k_bits: 1.0,
            remaining_budget_bits: 20.0 - (seq_no as f64),
            signature,
        }))
    }
}

fn resolution_hash(resolution: &OracleResolution) -> [u8; 32] {
    let bytes = serde_json::to_vec(resolution).expect("serde");
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

async fn setup(state: Arc<Mutex<State>>) -> (OraclePlusPlusBackend, Arc<Mutex<State>>) {
    let authority = SigningKey::from_bytes(&[7u8; 32]);
    let oracle = SigningKey::from_bytes(&[8u8; 32]);
    let resolution = OracleResolution::new(16, 0.01).expect("resolution");
    let svc = TestOracleSvc {
        authority: authority.clone(),
        oracle,
        resolution_hash: resolution_hash(&resolution),
        state: state.clone(),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        let incoming = TcpListenerStream::new(listener);
        let result = Server::builder()
            .add_service(OraclePlusPlusServer::new(svc))
            .serve_with_incoming(incoming)
            .await;
        let _ = result;
    });

    let cfg = OraclePlusPlusConfig {
        endpoint: format!("http://{}", addr),
        tls: None,
        trusted_authorities: vec![authority.verifying_key().to_bytes()],
        expected_oracle_id: "oracle-test".into(),
        expected_measurement_hash: Some([1; 32]),
        max_clock_skew_epochs: 2,
        require_canonical_bucket_bytes: true,
    };
    let mut backend = OraclePlusPlusBackend::connect(
        cfg,
        resolution,
        NullSpec {
            domain: "d".into(),
            null_accuracy: 0.5,
            e_value_fn: EValueFn::Fixed(1.0),
        },
        "holdout".into(),
    )
    .await
    .expect("connect");
    backend.handshake().await.expect("handshake");
    (backend, state)
}

#[tokio::test(flavor = "multi_thread")]
async fn happy_path_works() {
    let state = Arc::new(Mutex::new(State::default()));
    let (mut backend, _) = setup(state).await;
    let r = backend.query_reply("session-a", &[0, 1]).await;
    assert!(r.is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn tampered_bucket_bytes_rejected() {
    let state = Arc::new(Mutex::new(State {
        tamper_bucket: true,
        ..State::default()
    }));
    let (mut backend, _) = setup(state).await;
    let r = backend.query_reply("session-a", &[0, 1]).await;
    assert!(r.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn tampered_signature_rejected() {
    let state = Arc::new(Mutex::new(State {
        tamper_signature: true,
        ..State::default()
    }));
    let (mut backend, _) = setup(state).await;
    let r = backend.query_reply("session-a", &[0, 1]).await;
    assert!(r.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn replay_rejected() {
    let state = Arc::new(Mutex::new(State {
        replay: true,
        ..State::default()
    }));
    let (mut backend, _) = setup(state).await;
    let first = backend.query_reply("session-a", &[0, 1]).await;
    assert!(first.is_ok());
    let second = backend.query_reply("session-a", &[0, 1]).await;
    assert!(second.is_err());
}
