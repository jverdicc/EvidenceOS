use evidenceos_daemon::server::EvidenceOsService;
use evidenceos_protocol::pb;
use evidenceos_protocol::pb::evidence_os_client::EvidenceOsClient;
use evidenceos_protocol::pb::evidence_os_server::EvidenceOsServer;
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

fn wasm_with_payload(payload: &str) -> Vec<u8> {
    wat::parse_str(format!(
        r#"(module
          (import \"env\" \"oracle_bucket\" (func $oracle (param i32 i32) (result i32)))
          (import \"env\" \"emit_structured_claim\" (func $emit (param i32 i32) (result i32)))
          (memory (export \"memory\") 1)
          (data (i32.const 0) \"{payload}\")
          (func (export \"run")
            i32.const 0 i32.const {len} call $emit drop)
        )"#,
        len = payload.len()
    ))
    .expect("wat")
}

async fn create_and_seal(
    client: &mut EvidenceOsClient<Channel>,
    schema_id: &str,
    wasm: Vec<u8>,
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
                semantic_hash: vec![1; 32],
                phys_hir_signature_hash: vec![2; 32],
                dependency_merkle_root: vec![3; 32],
            }),
            holdout_ref: "h".into(),
            epoch_size: 10,
            oracle_num_symbols: 4,
            access_credit: 64,
        })
        .await
        .expect("create")
        .into_inner()
        .claim_id;

    client
        .commit_artifacts(pb::CommitArtifactsRequest {
            claim_id: claim_id.clone(),
            artifacts: vec![],
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

#[tokio::test]
async fn valid_cbrn_sc_output_passes_and_returns_capsule() {
    let temp = TempDir::new().expect("temp");
    let (_h, mut client) = start_server(temp.path().to_str().expect("path")).await;
    let payload = "{\"schema_version\":\"1\",\"claim_id\":\"c1\",\"event_time_unix\":1,\"substance\":\"chlorine\",\"unit\":\"ppm\",\"value\":1,\"confidence_bps\":9000,\"reason_code\":\"ALERT\",\"reason_codes\":[\"ALERT\"],\"references\":[],\"location_id\":\"l\",\"sensor_id\":\"s\"}";
    let claim_id = create_and_seal(&mut client, "cbrn-sc.v1", wasm_with_payload(payload)).await;
    client
        .execute_claim(pb::ExecuteClaimRequest {
            claim_id: claim_id.clone(),
            decision: pb::Decision::Approve as i32,
            reason_codes: vec![],
            canonical_output: vec![],
        })
        .await
        .expect("execute");
    let capsule = client
        .fetch_capsule(pb::FetchCapsuleRequest { claim_id })
        .await
        .expect("fetch")
        .into_inner();
    assert!(!capsule.capsule_bytes.is_empty());
}

#[tokio::test]
async fn invalid_cbrn_sc_fails_closed_without_etl_append() {
    let temp = TempDir::new().expect("temp");
    let (_h, mut client) = start_server(temp.path().to_str().expect("path")).await;
    let before = client
        .get_signed_tree_head(pb::GetSignedTreeHeadRequest {})
        .await
        .expect("sth")
        .into_inner()
        .tree_size;
    let bad_payload = "{\"schema_version\":\"1\",\"claim_id\":\"c1\",\"event_time_unix\":1,\"substance\":\"chlorine\",\"unit\":\"ppm\",\"value\":1.5,\"confidence_bps\":9000,\"reason_code\":\"ALERT\",\"reason_codes\":[\"ALERT\"],\"references\":[],\"location_id\":\"l\",\"sensor_id\":\"s\"}";
    let claim_id = create_and_seal(&mut client, "cbrn-sc.v1", wasm_with_payload(bad_payload)).await;
    assert!(client
        .execute_claim(pb::ExecuteClaimRequest {
            claim_id,
            decision: pb::Decision::Approve as i32,
            reason_codes: vec![],
            canonical_output: vec![]
        })
        .await
        .is_err());
    let after = client
        .get_signed_tree_head(pb::GetSignedTreeHeadRequest {})
        .await
        .expect("sth")
        .into_inner()
        .tree_size;
    assert_eq!(before, after);
}
