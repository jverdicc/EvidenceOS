use std::sync::Arc;

use axum::http::{HeaderMap, HeaderValue};
use parking_lot::Mutex;
use proptest::prelude::*;
use serde_json::{json, Map, Value};

use crate::config::DaemonConfig;
use crate::http_preflight::{
    preflight_tool_call_impl, stable_params_hash, HttpPreflightState, RateLimitState,
};
use crate::probe::{ProbeClock, ProbeConfig, ProbeDetector};
use crate::telemetry::Telemetry;

struct FixedClock;

impl ProbeClock for FixedClock {
    fn now_ms(&self) -> u64 {
        1_000
    }
}

fn state(cfg: DaemonConfig) -> HttpPreflightState {
    let mut probe_cfg = ProbeConfig::from_env();
    probe_cfg.throttle_total_requests = 2;
    probe_cfg.escalate_total_requests = 3;
    probe_cfg.freeze_total_requests = 4;
    HttpPreflightState {
        hard_freeze_ops: probe_cfg.freeze_total_requests,
        cfg: cfg.clone(),
        telemetry: Arc::new(Telemetry::new().expect("telemetry")),
        probe: Arc::new(Mutex::new(ProbeDetector::new(probe_cfg))),
        policy_oracles: Arc::new(Vec::new()),
        clock: Arc::new(FixedClock),
        rate_state: Arc::new(Mutex::new(RateLimitState::default())),
        high_risk_tools: Arc::new(cfg.preflight_high_risk_tools.into_iter().collect()),
    }
}

fn request_headers(request_id: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-request-id",
        HeaderValue::from_str(request_id).expect("request id"),
    );
    headers
}

#[tokio::test]
async fn invalid_tool_name_rejected() {
    let cfg = DaemonConfig::default();
    let st = state(cfg);
    let body = json!({"toolName":"","params":{}}).to_string();
    let err = preflight_tool_call_impl(&st, &request_headers("req-1"), body.as_bytes())
        .await
        .expect_err("must reject");
    assert_eq!(err.response.reason_code, "InvalidArgument");
}

#[tokio::test]
async fn params_not_object_rejected() {
    let cfg = DaemonConfig::default();
    let st = state(cfg);
    let body = json!({"toolName":"exec","params":[]}).to_string();
    let err = preflight_tool_call_impl(&st, &request_headers("req-2"), body.as_bytes())
        .await
        .expect_err("must reject");
    assert_eq!(err.response.reason_code, "InvalidArgument");
}

#[tokio::test]
async fn body_too_large_rejected() {
    let cfg = DaemonConfig {
        preflight_max_body_bytes: 8,
        ..DaemonConfig::default()
    };
    let st = state(cfg);
    let body = json!({"toolName":"exec","params":{"x":"123456789"}}).to_string();
    let err = preflight_tool_call_impl(&st, &request_headers("req-3"), body.as_bytes())
        .await
        .expect_err("must reject");
    assert_eq!(err.response.reason_code, "InvalidArgument");
}

#[tokio::test]
async fn requires_bearer_token_when_configured() {
    let cfg = DaemonConfig {
        preflight_require_bearer_token: Some("secret".to_string()),
        ..DaemonConfig::default()
    };
    let st = state(cfg);
    let body = json!({"toolName":"exec","params":{}}).to_string();
    let err = preflight_tool_call_impl(&st, &request_headers("req-4"), body.as_bytes())
        .await
        .expect_err("must reject");
    assert_eq!(err.response.reason_code, "Unauthorized");
}

#[tokio::test]
async fn probe_freeze_after_threshold() {
    let cfg = DaemonConfig::default();
    let st = state(cfg);
    let body = json!({"toolName":"exec","params":{},"sessionId":"s","agentId":"a"}).to_string();
    let headers = request_headers("req-freeze");

    let mut final_decision = String::new();
    for _ in 0..5 {
        let resp = preflight_tool_call_impl(&st, &headers, body.as_bytes())
            .await
            .expect("response");
        final_decision = resp.decision;
    }
    assert_eq!(final_decision, "DENY");
}

#[tokio::test]
async fn requires_request_id_header() {
    let cfg = DaemonConfig::default();
    let st = state(cfg);
    let body = json!({"toolName":"exec","params":{}}).to_string();
    let err = preflight_tool_call_impl(&st, &HeaderMap::new(), body.as_bytes())
        .await
        .expect_err("must reject");
    assert_eq!(err.response.reason_code, "InvalidArgument");
    assert_eq!(err.response.detail, None);
}

#[tokio::test]
async fn principal_comes_from_auth_not_agent_id() {
    let cfg = DaemonConfig {
        preflight_require_bearer_token: Some("secret".to_string()),
        ..DaemonConfig::default()
    };
    let st = state(cfg);
    let body_a =
        json!({"toolName":"exec","params":{},"sessionId":"s","agentId":"agent-a"}).to_string();
    let body_b =
        json!({"toolName":"exec","params":{},"sessionId":"s","agentId":"agent-b"}).to_string();

    let mut headers = request_headers("req-auth");
    headers.insert("authorization", HeaderValue::from_static("Bearer secret"));

    let first = preflight_tool_call_impl(&st, &headers, body_a.as_bytes())
        .await
        .expect("response");
    let second = preflight_tool_call_impl(&st, &headers, body_b.as_bytes())
        .await
        .expect("response");

    assert_eq!(first.decision, "ALLOW");
    assert_eq!(second.decision, "DOWNGRADE");
}

proptest! {
    #[test]
    fn fuzz_tool_name_ascii_bounds(name in "[ -~]{0,140}") {
        let valid = !name.is_empty() && name.len() <= 128 && name.chars().all(|c| c.is_ascii() && !c.is_ascii_control());
        let actual = !name.is_empty() && name.len() <= 128 && name.chars().all(|c| c.is_ascii() && !c.is_ascii_control());
        prop_assert_eq!(actual, valid);
    }

    #[test]
    fn fuzz_params_hash_deterministic(entries in proptest::collection::vec(("[a-z]{1,6}", any::<u64>()), 1..8)) {
        let mut map = Map::new();
        for (k, v) in entries {
            map.insert(k, Value::Number(v.into()));
        }
        let h1 = stable_params_hash(&map).expect("hash");
        let h2 = stable_params_hash(&map).expect("hash");
        prop_assert_eq!(h1, h2);
    }
}

#[tokio::test]
async fn invalid_inputs_use_constant_public_error_shape() {
    let st = state(DaemonConfig::default());
    let cases = [
        b"{".as_slice(),
        br#"{"toolName":"","params":{}}"#.as_slice(),
        br#"{"toolName":"exec","params":[]}"#.as_slice(),
    ];
    let mut lengths = std::collections::BTreeSet::new();
    for (idx, body) in cases.iter().enumerate() {
        let err = preflight_tool_call_impl(&st, &request_headers(&format!("req-{idx}")), body)
            .await
            .expect_err("must reject");
        let encoded = serde_json::to_vec(&err.response).expect("encode");
        lengths.insert(encoded.len());
        assert_eq!(err.response.reason_code, "INVALID_INPUT");
        assert!(err.response.detail.is_none());
    }
    assert_eq!(lengths.len(), 1);
}
