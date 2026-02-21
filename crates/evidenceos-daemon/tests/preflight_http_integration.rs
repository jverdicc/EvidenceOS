use std::sync::Arc;

use evidenceos_daemon::config::DaemonConfig;
use evidenceos_daemon::http_preflight;
use evidenceos_daemon::probe::{ProbeConfig, ProbeDetector};
use evidenceos_daemon::telemetry::Telemetry;
use parking_lot::Mutex;
use reqwest::StatusCode;
use serde_json::json;

#[tokio::test]
async fn preflight_http_allows_then_escalates() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");

    let mut probe_cfg = ProbeConfig::from_env();
    probe_cfg.throttle_total_requests = 2;
    probe_cfg.escalate_total_requests = 3;
    probe_cfg.freeze_total_requests = 4;

    let cfg = DaemonConfig {
        preflight_http_listen: Some(addr.to_string()),
        preflight_timeout_ms: 100,
        ..DaemonConfig::default()
    };

    let state = http_preflight::build_state(
        cfg,
        Arc::new(Telemetry::new().expect("telemetry")),
        Arc::new(Mutex::new(ProbeDetector::new(probe_cfg))),
        Arc::new(Vec::new()),
    );

    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let _ = http_preflight::serve(listener, state, async move {
            let _ = rx.await;
        })
        .await;
    });

    let client = reqwest::Client::new();
    let url = format!("http://{addr}/v1/preflight_tool_call");
    let payload = json!({
        "toolName":"exec",
        "params":{"cmd":"echo hello"},
        "sessionId":"sess-1",
        "agentId":"agent-1"
    });

    let first = client
        .post(&url)
        .header("x-request-id", "req-1")
        .json(&payload)
        .send()
        .await
        .expect("first");
    assert_eq!(first.status(), StatusCode::OK);
    let first_json: serde_json::Value = first.json().await.expect("json");
    assert_eq!(first_json["decision"], "ALLOW");
    assert!(!first_json["reasonCode"]
        .as_str()
        .unwrap_or_default()
        .is_empty());

    let mut seen_transition = false;
    for _ in 0..5 {
        let resp = client
            .post(&url)
            .header("x-request-id", "req-loop")
            .json(&payload)
            .send()
            .await
            .expect("resp");
        assert_eq!(resp.status(), StatusCode::OK);
        let v: serde_json::Value = resp.json().await.expect("json");
        let decision = v["decision"].as_str().unwrap_or_default();
        assert!(matches!(
            decision,
            "ALLOW" | "DOWNGRADE" | "REQUIRE_HUMAN" | "DENY"
        ));
        let reason = v["reasonCode"].as_str().unwrap_or_default();
        assert!(!reason.is_empty());
        if matches!(decision, "DOWNGRADE" | "REQUIRE_HUMAN" | "DENY") {
            seen_transition = true;
        }
    }
    assert!(seen_transition);

    let _ = tx.send(());
    server.abort();
}
