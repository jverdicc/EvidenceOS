use evidenceos_core::structured_claims;
use evidenceos_daemon::server::EvidenceOsService;
use evidenceos_protocol::pb;
use evidenceos_protocol::pb::evidence_os_client::EvidenceOsClient;
use evidenceos_protocol::pb::evidence_os_server::EvidenceOsServer;
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{transport::Channel, transport::Server};

async fn start_server(data_dir: &str) -> (tokio::task::JoinHandle<()>, EvidenceOsClient<Channel>) {
    let svc = EvidenceOsService::build(data_dir).expect("service");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let incoming = TcpListenerStream::new(listener);
    let handle = tokio::spawn(async move {
        Server::builder()
            .add_service(EvidenceOsServer::new(svc))
            .serve_with_incoming(incoming)
            .await
            .expect("server run");
    });
    let client = EvidenceOsClient::connect(format!("http://{addr}"))
        .await
        .expect("connect");
    (handle, client)
}

fn wat_string_bytes(bytes: &[u8]) -> String {
    let mut out = String::new();
    for b in bytes {
        out.push_str(&format!("\\{:02x}", b));
    }
    out
}

fn wasm_with_payload(payload: &[u8]) -> Vec<u8> {
    let escaped = wat_string_bytes(payload);
    wat::parse_str(format!(
        r#"(module
          (import "env" "emit_structured_claim" (func $emit (param i32 i32) (result i32)))
          (memory (export "memory") 1)
          (data (i32.const 0) "{escaped}")
          (func (export "run")
            i32.const 0 i32.const {len} call $emit drop)
        )"#,
        len = payload.len()
    ))
    .expect("wat")
}

async fn create_and_seal_with_signals(
    client: &mut EvidenceOsClient<Channel>,
    schema_id: &str,
    wasm: Vec<u8>,
    semantic_hash: Vec<u8>,
    physhir_hash: Vec<u8>,
    lineage_root_hash: Vec<u8>,
) -> Vec<u8> {
    let claim_id = client
        .create_claim_v2(pb::CreateClaimV2Request {
            claim_name: "c".into(),
            metadata: Some(pb::ClaimMetadataV2 {
                lane: "fast".into(),
                alpha_micros: 50_000,
                epoch_config_ref: "epoch".into(),
                output_schema_id: schema_id.into(),
            }),
            signals: Some(pb::TopicSignalsV2 {
                semantic_hash,
                phys_hir_signature_hash: physhir_hash,
                dependency_merkle_root: lineage_root_hash,
            }),
            holdout_ref: "h".into(),
            epoch_size: 10,
            oracle_num_symbols: 4,
            access_credit: 4096,

            oracle_id: "builtin.accuracy".to_string(),
            nullspec_id: String::new(),
        })
        .await
        .expect("create")
        .into_inner()
        .claim_id;

    client
        .commit_artifacts(pb::CommitArtifactsRequest {
            claim_id: claim_id.clone(),
            artifacts: vec![pb::Artifact {
                kind: "wasm".into(),
                artifact_hash: {
                    let mut h = Sha256::new();
                    h.update(&wasm);
                    h.finalize().to_vec()
                },
            }],
            wasm_module: wasm,
        })
        .await
        .expect("commit");
    client
        .freeze_gates(pb::FreezeGatesRequest {
            claim_id: claim_id.clone(),
        })
        .await
        .expect("freeze");
    client
        .seal_claim(pb::SealClaimRequest {
            claim_id: claim_id.clone(),
        })
        .await
        .expect("seal");
    claim_id
}

async fn create_and_seal(
    client: &mut EvidenceOsClient<Channel>,
    schema_id: &str,
    wasm: Vec<u8>,
) -> Vec<u8> {
    create_and_seal_with_signals(
        client,
        schema_id,
        wasm,
        vec![1; 32],
        vec![2; 32],
        vec![3; 32],
    )
    .await
}
#[tokio::test]
async fn valid_cbrn_sc_output_passes_and_returns_capsule() {
    let temp = TempDir::new().expect("temp");
    let (_h, mut client) = start_server(temp.path().to_str().expect("path")).await;
    let payload = b"{\"version\":1,\"profile\":\"CBRN_SC_V1\",\"domain\":\"CHEMICAL\",\"claim_kind\":\"MEASUREMENT\",\"claim_id\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"sensor_id\":\"ABCDEFGH234567AB\",\"event_time_unix\":1,\"quantities\":[{\"kind\":\"CONCENTRATION\",\"value\":{\"value\":\"1\",\"scale\":0},\"unit\":\"ppm\"}],\"unit_system\":\"PHYSHIR_UCUM_SUBSET\",\"envelope_id\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"envelope_check\":\"PASS\",\"references\":[]}";
    let claim_id = create_and_seal(&mut client, "cbrn-sc.v1", wasm_with_payload(payload)).await;
    let exec = client
        .execute_claim_v2(pb::ExecuteClaimV2Request {
            claim_id: claim_id.clone(),
        })
        .await
        .expect("execute")
        .into_inner();
    assert!(!exec.canonical_output.is_empty());
    let capsule = client
        .fetch_capsule(pb::FetchCapsuleRequest { claim_id })
        .await
        .expect("fetch")
        .into_inner();
    assert!(!capsule.capsule_bytes.is_empty());
}

#[tokio::test]
async fn structured_invalid_reason_code_unknown_field_and_float_are_rejected() {
    let temp = TempDir::new().expect("temp");
    let (_h, mut client) = start_server(temp.path().to_str().expect("path")).await;

    for payload in [
        b"{\"version\":1,\"profile\":\"CBRN_SC_V1\",\"domain\":\"NOPE\",\"claim_kind\":\"MEASUREMENT\",\"claim_id\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"sensor_id\":\"ABCDEFGH234567AB\",\"event_time_unix\":1,\"quantities\":[{\"kind\":\"CONCENTRATION\",\"value\":{\"value\":\"1\",\"scale\":0},\"unit\":\"ppm\"}],\"unit_system\":\"PHYSHIR_UCUM_SUBSET\",\"envelope_id\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"envelope_check\":\"PASS\",\"references\":[]}".as_slice(),
        b"{\"version\":1,\"profile\":\"CBRN_SC_V1\",\"domain\":\"CHEMICAL\",\"claim_kind\":\"MEASUREMENT\",\"claim_id\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"sensor_id\":\"ABCDEFGH234567AB\",\"event_time_unix\":1,\"quantities\":[{\"kind\":\"CONCENTRATION\",\"value\":{\"value\":\"1\",\"scale\":0},\"unit\":\"ppm\"}],\"unit_system\":\"PHYSHIR_UCUM_SUBSET\",\"envelope_id\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"envelope_check\":\"PASS\",\"references\":[],\"unexpected\":1}".as_slice(),
        b"{\"version\":1,\"profile\":\"CBRN_SC_V1\",\"domain\":\"CHEMICAL\",\"claim_kind\":\"MEASUREMENT\",\"claim_id\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"sensor_id\":\"ABCDEFGH234567AB\",\"event_time_unix\":1,\"quantities\":[{\"kind\":\"CONCENTRATION\",\"value\":{\"value\":1.5,\"scale\":0},\"unit\":\"ppm\"}],\"unit_system\":\"PHYSHIR_UCUM_SUBSET\",\"envelope_id\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"envelope_check\":\"PASS\",\"references\":[]}".as_slice(),
    ] {
        let claim_id = create_and_seal(&mut client, "cbrn-sc.v1", wasm_with_payload(payload)).await;
        let err = client
            .execute_claim_v2(pb::ExecuteClaimV2Request { claim_id })
            .await
            .expect_err("invalid structured output should fail");
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    }
}

#[tokio::test]
async fn structured_output_too_large_rejected() {
    let temp = TempDir::new().expect("temp");
    let (_h, mut client) = start_server(temp.path().to_str().expect("path")).await;
    let refs = "x".repeat(structured_claims::max_bytes_upper_bound() as usize + 32);
    let payload = format!(
        "{{\"version\":1,\"profile\":\"CBRN_SC_V1\",\"domain\":\"CHEMICAL\",\"claim_kind\":\"MEASUREMENT\",\"claim_id\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"sensor_id\":\"ABCDEFGH234567AB\",\"event_time_unix\":1,\"quantities\":[{{\"kind\":\"CONCENTRATION\",\"value\":{{\"value\":\"1\",\"scale\":0}},\"unit\":\"ppm\"}}],\"unit_system\":\"PHYSHIR_UCUM_SUBSET\",\"envelope_id\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"envelope_check\":\"PASS\",\"references\":[\"{}\"]}}",
        refs
    );
    let claim_id = create_and_seal(
        &mut client,
        "cbrn-sc.v1",
        wasm_with_payload(payload.as_bytes()),
    )
    .await;
    let err = client
        .execute_claim_v2(pb::ExecuteClaimV2Request { claim_id })
        .await
        .expect_err("too large output should fail");
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
}

#[tokio::test]
async fn lineage_root_changes_topic_id_by_design() {
    let temp = TempDir::new().expect("temp");
    let (_h, mut client) = start_server(temp.path().to_str().expect("path")).await;
    let req_a = pb::CreateClaimV2Request {
        claim_name: "lineage-a".into(),
        metadata: Some(pb::ClaimMetadataV2 {
            lane: "fast".into(),
            alpha_micros: 50_000,
            epoch_config_ref: "epoch".into(),
            output_schema_id: "cbrn-sc.v1".into(),
        }),
        signals: Some(pb::TopicSignalsV2 {
            semantic_hash: vec![1; 32],
            phys_hir_signature_hash: vec![2; 32],
            dependency_merkle_root: vec![3; 32],
        }),
        holdout_ref: "h".into(),
        epoch_size: 10,
        oracle_num_symbols: 4,
        access_credit: 4096,

        oracle_id: "builtin.accuracy".to_string(),
        nullspec_id: String::new(),
    };
    let req_b = pb::CreateClaimV2Request {
        signals: Some(pb::TopicSignalsV2 {
            semantic_hash: vec![1; 32],
            phys_hir_signature_hash: vec![2; 32],
            dependency_merkle_root: vec![4; 32],
        }),
        claim_name: "lineage-b".into(),
        oracle_id: "builtin.accuracy".to_string(),
        nullspec_id: String::new(),
        ..req_a.clone()
    };
    let a = client
        .create_claim_v2(req_a)
        .await
        .expect("create a")
        .into_inner();
    let b = client
        .create_claim_v2(req_b)
        .await
        .expect("create b")
        .into_inner();
    assert_ne!(a.topic_id, b.topic_id);
}
