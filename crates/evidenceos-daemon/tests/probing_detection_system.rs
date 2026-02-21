use std::path::Path;
use std::sync::Arc;

use evidenceos_daemon::server::EvidenceOsService;
use evidenceos_daemon::telemetry::Telemetry;
use evidenceos_protocol::pb;
use evidenceos_protocol::pb::evidence_os_server::EvidenceOs;
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tonic::{Code, Request};

fn hash32(seed: u8) -> Vec<u8> {
    vec![seed; 32]
}

#[tokio::test]
async fn probing_detection_grades_response_and_emits_evidence() {
    let dir = TempDir::new().expect("tmp");
    let data_dir = dir.path().join("data");
    std::fs::create_dir_all(&data_dir).expect("mkdir");
    let telemetry = Arc::new(Telemetry::new().expect("telemetry"));
    let svc = EvidenceOsService::build_with_options(
        &data_dir.to_string_lossy(),
        false,
        telemetry.clone(),
    )
    .expect("service");

    let mut saw_throttle = false;
    let mut saw_freeze = false;
    for i in 0u8..100u8 {
        let req = pb::CreateClaimV2Request {
            claim_name: format!("probe-{i}"),
            holdout_ref: "holdout-1".to_string(),
            access_credit: 10,
            oracle_num_symbols: 8,
            epoch_size: 1,
            metadata: Some(pb::ClaimMetadataV2 {
                lane: "fast".to_string(),
                alpha_micros: 500_000,
                epoch_config_ref: "epoch-v1".to_string(),
                output_schema_id: "legacy/v1".to_string(),
            }),
            signals: Some(pb::TopicSignalsV2 {
                semantic_hash: Sha256::digest([i]).to_vec(),
                phys_hir_signature_hash: hash32(7),
                dependency_merkle_root: vec![],
            }),

            oracle_id: "builtin.accuracy".to_string(),
            nullspec_id: String::new(),
        };
        let mut request = Request::new(req);
        request.metadata_mut().insert(
            "authorization",
            "Bearer probe-token".parse().expect("metadata"),
        );
        match svc.create_claim_v2(request).await {
            Ok(_) => {}
            Err(status) if status.code() == Code::ResourceExhausted => {
                saw_throttle = true;
                assert!(status.message().contains("PROBE_THROTTLED"));
            }
            Err(status) if status.code() == Code::PermissionDenied => {
                saw_freeze = true;
                assert!(status.message().contains("PROBE_FROZEN"));
                break;
            }
            Err(status) => panic!("unexpected status: {status}"),
        }
    }

    assert!(saw_throttle, "should throttle before freeze");
    assert!(saw_freeze, "should freeze after persistent probing");

    let metrics = telemetry.render();
    assert!(metrics.contains("probe_throttled_total"));
    assert!(metrics.contains("probe_frozen_total"));

    let etl_bytes = std::fs::read(data_dir.join("etl.log")).expect("etl");
    let etl_text = String::from_utf8_lossy(&etl_bytes);
    assert!(etl_text.contains("probe_event"));

    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("repo root");
    let artifacts_dir = repo_root.join("artifacts/probing");
    std::fs::create_dir_all(&artifacts_dir).expect("artifact dir");
    let artifact = serde_json::json!({
        "test": "probing_detection_grades_response_and_emits_evidence",
        "saw_throttle": saw_throttle,
        "saw_freeze": saw_freeze,
        "metrics_excerpt": metrics.lines().filter(|l| l.contains("probe_")).collect::<Vec<_>>(),
    });
    std::fs::write(
        artifacts_dir.join("probing_detection_system.json"),
        serde_json::to_string_pretty(&artifact).expect("json"),
    )
    .expect("write artifact");
}
