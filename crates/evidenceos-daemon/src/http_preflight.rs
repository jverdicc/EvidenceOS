use std::collections::HashSet;
use std::fs::OpenOptions;
use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use axum::extract::State;
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::post;
use axum::{Json, Router};
use evidenceos_core::capsule::canonical_json;
use evidenceos_core::error::EvidenceOSError;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;

use crate::config::DaemonConfig;
use crate::policy_oracle::{PolicyOracleEngine, PreflightPolicyDecision};
use crate::probe::{
    ProbeClock, ProbeDetector, ProbeObservation, ProbeSnapshot, ProbeVerdict, SystemClock,
};
use crate::public_error::PublicErrorCode;
use crate::telemetry::Telemetry;

#[derive(Debug, Clone, Deserialize)]
#[allow(non_snake_case)]
pub struct PreflightToolCallRequest {
    pub toolName: String,
    pub params: Map<String, Value>,
    pub paramsHash: Option<String>,
    pub sessionId: Option<String>,
    pub agentId: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[allow(non_snake_case)]
pub struct PreflightToolCallResponse {
    pub decision: String,
    #[serde(rename = "reasonCode")]
    pub reason_code: String,
    #[serde(rename = "reasonDetail", skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rewrittenParams: Option<Map<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budgetDelta: Option<BudgetDelta>,
    #[serde(rename = "paramsHash", skip_serializing_if = "Option::is_none")]
    pub paramsHash: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(non_snake_case)]
pub struct PostflightToolCallRequest {
    pub toolName: String,
    pub sessionId: Option<String>,
    pub agentId: Option<String>,
    pub paramsHash: String,
    pub preflightReceiptHash: Option<String>,
    pub status: String,
    pub output: Option<Value>,
    pub outputBytes: Option<u64>,
    pub outputHash: Option<String>,
    pub errorMessage: Option<String>,
    pub startedAtMs: Option<u64>,
    pub endedAtMs: Option<u64>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[allow(non_snake_case)]
pub struct PostflightToolCallResponse {
    pub decision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outputRewrite: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lane: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budgetDelta: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budgetRemainingBits: Option<f64>,
    pub receiptHash: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct BudgetDelta {
    pub spent: u64,
    pub remaining: u64,
}

#[derive(Clone)]
pub struct HttpPreflightState {
    pub cfg: DaemonConfig,
    pub telemetry: Arc<Telemetry>,
    pub probe: Arc<Mutex<ProbeDetector>>,
    pub policy_oracles: Arc<Vec<PolicyOracleEngine>>,
    pub hard_freeze_ops: usize,
    pub clock: Arc<dyn ProbeClock>,
    pub rate_state: Arc<Mutex<RateLimitState>>,
    pub high_risk_tools: Arc<HashSet<String>>,
    pub postflight_etl_path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct RateLimitState {
    started_at: Instant,
    count: u32,
}

impl Default for RateLimitState {
    fn default() -> Self {
        Self {
            started_at: Instant::now(),
            count: 0,
        }
    }
}

pub fn router(state: HttpPreflightState) -> Router {
    Router::new()
        .route("/v1/preflight_tool_call", post(preflight_tool_call))
        .route("/v1/postflight_tool_call", post(postflight_tool_call))
        .layer(RequestBodyLimitLayer::new(
            state.cfg.preflight_max_body_bytes,
        ))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

pub async fn serve(
    listener: tokio::net::TcpListener,
    state: HttpPreflightState,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<(), std::io::Error> {
    axum::serve(listener, router(state))
        .with_graceful_shutdown(shutdown)
        .await
}

async fn preflight_tool_call(
    State(state): State<HttpPreflightState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    let started = Instant::now();
    let outcome = preflight_tool_call_impl(&state, &headers, &body).await;
    state
        .telemetry
        .record_preflight_latency_ms(started.elapsed().as_millis() as u64);
    match outcome {
        Ok(resp) => {
            state
                .telemetry
                .record_preflight_request(&resp.decision, &resp.reason_code);
            (StatusCode::OK, Json(resp)).into_response()
        }
        Err(err) => {
            state.telemetry.record_preflight_failure(err.kind);
            state
                .telemetry
                .record_preflight_request(&err.response.decision, &err.response.reason_code);
            (err.status, Json(err.response)).into_response()
        }
    }
}

async fn postflight_tool_call(
    State(state): State<HttpPreflightState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    match postflight_tool_call_impl(&state, &headers, &body).await {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err(err) => (err.status, Json(err.response)).into_response(),
    }
}

#[derive(Debug)]
pub struct HttpErr {
    pub(crate) status: StatusCode,
    pub(crate) kind: &'static str,
    pub(crate) response: PreflightToolCallResponse,
    _source: EvidenceOSError,
}

impl HttpErr {
    fn invalid_argument(_detail: &str, kind: &'static str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            kind,
            response: PreflightToolCallResponse {
                decision: "DENY".to_string(),
                reason_code: PublicErrorCode::InvalidInput.as_str().to_string(),
                detail: None,
                rewrittenParams: None,
                budgetDelta: None,
                paramsHash: None,
            },
            _source: EvidenceOSError::InvalidArgument,
        }
    }

    fn unauthorized() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            kind: "unauthorized",
            response: PreflightToolCallResponse {
                decision: "DENY".to_string(),
                reason_code: PublicErrorCode::Unauthorized.as_str().to_string(),
                detail: None,
                rewrittenParams: None,
                budgetDelta: None,
                paramsHash: None,
            },
            _source: EvidenceOSError::InvalidArgument,
        }
    }

    fn too_many_requests() -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            kind: "rate_limited",
            response: PreflightToolCallResponse {
                decision: "DOWNGRADE".to_string(),
                reason_code: PublicErrorCode::RateLimited.as_str().to_string(),
                detail: None,
                rewrittenParams: None,
                budgetDelta: None,
                paramsHash: None,
            },
            _source: EvidenceOSError::Frozen,
        }
    }

    fn from_policy_failure(cfg: &DaemonConfig) -> Self {
        let decision = if cfg.preflight_fail_open_for_low_risk {
            "ALLOW"
        } else {
            "REQUIRE_HUMAN"
        };
        Self {
            status: StatusCode::OK,
            kind: "policy_timeout",
            response: PreflightToolCallResponse {
                decision: decision.to_string(),
                reason_code: PublicErrorCode::Unavailable.as_str().to_string(),
                detail: None,
                rewrittenParams: None,
                budgetDelta: None,
                paramsHash: None,
            },
            _source: EvidenceOSError::Internal,
        }
    }
}

#[allow(clippy::result_large_err)]
pub async fn preflight_tool_call_impl(
    state: &HttpPreflightState,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<PreflightToolCallResponse, HttpErr> {
    if body.len() > state.cfg.preflight_max_body_bytes {
        return Err(HttpErr::invalid_argument(
            "request body too large",
            "body_too_large",
        ));
    }
    validate_authorization(headers, &state.cfg)?;
    let request_id = validate_request_id(headers)?;
    enforce_rate_limit(state)?;

    let value: Value = serde_json::from_slice(body)
        .map_err(|_| HttpErr::invalid_argument("invalid JSON body", "invalid_json"))?;
    let req: PreflightToolCallRequest = serde_json::from_value(value)
        .map_err(|_| HttpErr::invalid_argument("params must be an object", "params_not_object"))?;

    validate_ascii_printable_len(&req.toolName, 1, 128, "toolName")?;
    if let Some(session) = req.sessionId.as_deref() {
        validate_ascii_printable_len(session, 0, 128, "sessionId")?;
    }
    if let Some(agent) = req.agentId.as_deref() {
        validate_ascii_printable_len(agent, 0, 128, "agentId")?;
    }
    let is_high_risk = state.high_risk_tools.contains(&req.toolName);
    if is_high_risk
        && req
            .sessionId
            .as_deref()
            .map(|s| s.is_empty())
            .unwrap_or(true)
    {
        return Err(HttpErr {
            status: StatusCode::BAD_REQUEST,
            kind: "session_required",
            response: PreflightToolCallResponse {
                decision: "DENY".to_string(),
                reason_code: "SESSION_REQUIRED".to_string(),
                detail: maybe_auditor_detail(headers, "sessionId is required for high-risk tools"),
                rewrittenParams: None,
                budgetDelta: None,
                paramsHash: None,
            },
            _source: EvidenceOSError::InvalidArgument,
        });
    }

    let params_canonical = canonical_json(&req.params)
        .map_err(|_| HttpErr::invalid_argument("invalid params object", "params_canonical"))?;
    let params_hash = stable_params_hash(&req.params)
        .map_err(|_| HttpErr::invalid_argument("invalid params object", "params_hash"))?;
    if let Some(client_hash) = req.paramsHash.as_deref() {
        validate_hex_64(client_hash)
            .map_err(|_| HttpErr::invalid_argument("invalid paramsHash", "invalid_params_hash"))?;
        if client_hash != params_hash {
            return Err(HttpErr::invalid_argument(
                "paramsHash mismatch",
                "params_hash_mismatch",
            ));
        }
    }

    let principal = principal_id_from_auth(headers);
    let operation = req
        .sessionId
        .clone()
        .unwrap_or_else(|| "no-session".to_string());

    let now_ms = state.clock.now_ms();
    let (probe_verdict, snapshot) = {
        let mut guard = state.probe.lock();
        guard.observe(
            &ProbeObservation {
                principal_id: principal.clone(),
                operation_id: operation.clone(),
                topic_id: req.toolName.clone(),
                semantic_hash: params_hash.clone(),
            },
            now_ms,
        )
    };

    let mut response = map_probe_verdict(&probe_verdict, &snapshot, state.hard_freeze_ops);
    response.paramsHash = Some(params_hash.clone());
    tracing::info!(
        request_id = %request_id,
        tool_name = %req.toolName,
        principal_id = %principal,
        session_id = %operation,
        agent_id = ?req.agentId,
        params_hash = %params_hash,
        decision = %response.decision,
        reason_code = %response.reason_code,
        "preflight probe evaluated"
    );

    let policy_result = tokio::time::timeout(
        std::time::Duration::from_millis(state.cfg.preflight_timeout_ms),
        async {
            evaluate_policy(
                &state.policy_oracles,
                &req.toolName,
                &params_canonical,
                req.agentId.as_deref(),
                req.sessionId.as_deref(),
            )
        },
    )
    .await
    .map_err(|_| HttpErr::from_policy_failure(&state.cfg))?;

    apply_policy_veto(&mut response, policy_result);

    if response.decision == "DOWNGRADE" {
        response.rewrittenParams =
            downgrade_params(&req.toolName, &req.params, &state.high_risk_tools);
        if response.rewrittenParams.is_none() {
            response.decision = "DENY".to_string();
            response.reason_code = "UNSAFE_REWRITE".to_string();
            response.detail = maybe_auditor_detail(headers, "unable to safely rewrite parameters");
        }
    }

    tracing::info!(
        request_id = %request_id,
        tool_name = %req.toolName,
        principal_id = %principal,
        session_id = %operation,
        agent_id = ?req.agentId,
        decision = %response.decision,
        reason_code = %response.reason_code,
        "preflight decision"
    );
    tracing::info!(
        target: "evidenceos.preflight.audit",
        request_id = %request_id,
        principal_id = %principal,
        tool_name = %req.toolName,
        session_id = ?req.sessionId,
        agent_id = ?req.agentId,
        decision = %response.decision,
        reason_code = %response.reason_code,
        "preflight audit event"
    );
    Ok(response)
}

#[derive(Debug)]
pub struct PostflightHttpErr {
    pub(crate) status: StatusCode,
    pub(crate) response: PostflightToolCallResponse,
}

impl PostflightHttpErr {
    fn invalid(reason: &str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            response: PostflightToolCallResponse {
                decision: "BLOCK".to_string(),
                reason: Some(reason.to_string()),
                outputRewrite: None,
                lane: None,
                budgetDelta: None,
                budgetRemainingBits: None,
                receiptHash: String::new(),
            },
        }
    }
}

#[allow(clippy::result_large_err)]
pub async fn postflight_tool_call_impl(
    state: &HttpPreflightState,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<PostflightToolCallResponse, PostflightHttpErr> {
    validate_authorization(headers, &state.cfg)
        .map_err(|_| PostflightHttpErr::invalid("unauthorized"))?;
    let _ = validate_request_id(headers)
        .map_err(|_| PostflightHttpErr::invalid("missing_request_id"))?;
    let req: PostflightToolCallRequest =
        serde_json::from_slice(body).map_err(|_| PostflightHttpErr::invalid("invalid_json"))?;
    validate_ascii_printable_len(&req.toolName, 1, 128, "toolName")
        .map_err(|_| PostflightHttpErr::invalid("invalid_tool_name"))?;
    validate_hex_64(&req.paramsHash)
        .map_err(|_| PostflightHttpErr::invalid("invalid_params_hash"))?;
    if let Some(h) = req.outputHash.as_deref() {
        validate_hex_64(h).map_err(|_| PostflightHttpErr::invalid("invalid_output_hash"))?;
    }
    if let Some(h) = req.preflightReceiptHash.as_deref() {
        validate_hex_64(h)
            .map_err(|_| PostflightHttpErr::invalid("invalid_preflight_receipt_hash"))?;
    }
    if let Some(session) = req.sessionId.as_deref() {
        validate_ascii_printable_len(session, 0, 128, "sessionId")
            .map_err(|_| PostflightHttpErr::invalid("invalid_session_id"))?;
    }
    if state.high_risk_tools.contains(&req.toolName)
        && req
            .sessionId
            .as_deref()
            .map(|s| s.is_empty())
            .unwrap_or(true)
    {
        return Err(PostflightHttpErr::invalid("session_required"));
    }

    let output_json = req
        .output
        .as_ref()
        .map(|v| serde_json::to_vec(v).unwrap_or_default());
    let output_len = output_json
        .as_ref()
        .map(|v| v.len() as u64)
        .or(req.outputBytes)
        .unwrap_or(0);
    let output_hash = req
        .outputHash
        .clone()
        .or_else(|| output_json.as_ref().map(|v| hex::encode(sha256_bytes(v))));

    let operation = req
        .sessionId
        .clone()
        .unwrap_or_else(|| "no-session".to_string());
    let principal = principal_id_from_auth(headers);
    let semantic_hash = output_hash
        .clone()
        .unwrap_or_else(|| req.paramsHash.clone());
    let now_ms = state.clock.now_ms();
    let (probe_verdict, snapshot) = {
        let mut guard = state.probe.lock();
        guard.observe(
            &ProbeObservation {
                principal_id: principal,
                operation_id: operation,
                topic_id: req.toolName.clone(),
                semantic_hash,
            },
            now_ms,
        )
    };
    let mut decision = match probe_verdict {
        ProbeVerdict::Clean => "ALLOW".to_string(),
        ProbeVerdict::Throttle { .. } => "REDACT".to_string(),
        ProbeVerdict::Escalate { .. } => "REQUIRE_HUMAN".to_string(),
        ProbeVerdict::Freeze { .. } => "BLOCK".to_string(),
    };
    let mut reason = None;
    let mut output_rewrite = None;
    if req.status != "ok" && req.status != "error" {
        return Err(PostflightHttpErr::invalid("invalid_status"));
    }

    let max_bytes = state.cfg.postflight_default_max_output_bytes as u64;
    if let Some(raw) = req.output.as_ref() {
        if output_len > max_bytes {
            decision = "REDACT".to_string();
            let preview = serde_json::to_string(raw).unwrap_or_default();
            let preview: String = preview
                .chars()
                .take(state.cfg.postflight_preview_chars)
                .collect();
            output_rewrite = Some(json!({
                "truncated": true,
                "len": output_len,
                "sha256": output_hash.clone().unwrap_or_default(),
                "preview": preview,
            }));
            reason = Some("output_too_large".to_string());
        }
    }

    let budget_delta = 1.0;
    let budget_remaining = state
        .hard_freeze_ops
        .saturating_sub(snapshot.unique_semantic_hashes_operation)
        as f64;

    let mut response = PostflightToolCallResponse {
        decision,
        reason,
        outputRewrite: output_rewrite,
        lane: None,
        budgetDelta: Some(budget_delta),
        budgetRemainingBits: Some(budget_remaining),
        receiptHash: String::new(),
    };
    let receipt_payload = json!({
        "request": {
            "toolName": req.toolName,
            "sessionId": req.sessionId,
            "agentId": req.agentId,
            "paramsHash": req.paramsHash,
            "outputHash": output_hash,
        },
        "response": response.clone(),
    });
    let canonical = canonical_json(&receipt_payload)
        .map_err(|_| PostflightHttpErr::invalid("receipt_canonical"))?;
    response.receiptHash = hex::encode(sha256_bytes(&canonical));

    let etl_record = json!({
        "schema": "evidenceos.v2.postflight",
        "toolName": receipt_payload["request"]["toolName"],
        "sessionId": receipt_payload["request"]["sessionId"],
        "agentId": receipt_payload["request"]["agentId"],
        "paramsHash": receipt_payload["request"]["paramsHash"],
        "outputHash": receipt_payload["request"]["outputHash"],
        "decision": response.decision,
        "receiptHash": response.receiptHash,
    });
    append_postflight_etl(&state.postflight_etl_path, &etl_record)
        .map_err(|_| PostflightHttpErr::invalid("etl_persist_failed"))?;
    Ok(response)
}

fn append_postflight_etl(path: &PathBuf, record: &Value) -> Result<(), std::io::Error> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    serde_json::to_writer(&mut file, record)?;
    file.write_all(
        b"
",
    )?;
    Ok(())
}

fn validate_hex_64(v: &str) -> Result<(), ()> {
    if v.len() != 64 || !v.as_bytes().iter().all(|b| b.is_ascii_hexdigit()) {
        return Err(());
    }
    Ok(())
}

pub fn stable_params_hash(params: &Map<String, Value>) -> Result<String, EvidenceOSError> {
    let canonical = canonical_json(params)?;
    let mut hash = Sha256::new();
    hash.update(canonical);
    Ok(hex::encode(hash.finalize()))
}

fn evaluate_policy(
    engines: &[PolicyOracleEngine],
    tool_name: &str,
    params_canonical_json: &[u8],
    agent_id: Option<&str>,
    session_id: Option<&str>,
) -> PreflightPolicyDecision {
    let mut decision = PreflightPolicyDecision::Approve {
        reason: "no_policy_oracle".to_string(),
    };
    for engine in engines {
        match engine.preflight_tool_call(tool_name, params_canonical_json, agent_id, session_id) {
            PreflightPolicyDecision::Reject { reason } => {
                return PreflightPolicyDecision::Reject { reason };
            }
            PreflightPolicyDecision::Defer { reason } => {
                decision = PreflightPolicyDecision::Defer { reason };
            }
            PreflightPolicyDecision::Approve { .. } => {}
        }
    }
    decision
}

fn map_probe_verdict(
    verdict: &ProbeVerdict,
    snapshot: &ProbeSnapshot,
    hard_freeze_ops: usize,
) -> PreflightToolCallResponse {
    let remaining = hard_freeze_ops.saturating_sub(snapshot.total_requests_operation) as u64;
    let budget = Some(BudgetDelta {
        spent: 1,
        remaining,
    });
    if snapshot.total_requests_operation >= hard_freeze_ops {
        return PreflightToolCallResponse {
            decision: "DENY".to_string(),
            reason_code: "PROBE_FREEZE".to_string(),
            detail: None,
            rewrittenParams: None,
            budgetDelta: budget,
            paramsHash: None,
        };
    }
    match verdict {
        ProbeVerdict::Clean => PreflightToolCallResponse {
            decision: "ALLOW".to_string(),
            reason_code: "PROBE_CLEAN".to_string(),
            detail: None,
            rewrittenParams: None,
            budgetDelta: budget,
            paramsHash: None,
        },
        ProbeVerdict::Throttle { reason: _, .. } => PreflightToolCallResponse {
            decision: "DOWNGRADE".to_string(),
            reason_code: "PROBE_THROTTLE".to_string(),
            detail: None,
            rewrittenParams: None,
            budgetDelta: budget,
            paramsHash: None,
        },
        ProbeVerdict::Escalate { reason: _ } => PreflightToolCallResponse {
            decision: "REQUIRE_HUMAN".to_string(),
            reason_code: "PROBE_ESCALATE".to_string(),
            detail: None,
            rewrittenParams: None,
            budgetDelta: budget,
            paramsHash: None,
        },
        ProbeVerdict::Freeze { reason: _ } => PreflightToolCallResponse {
            decision: "DENY".to_string(),
            reason_code: "PROBE_FREEZE".to_string(),
            detail: None,
            rewrittenParams: None,
            budgetDelta: budget,
            paramsHash: None,
        },
    }
}

fn apply_policy_veto(response: &mut PreflightToolCallResponse, policy: PreflightPolicyDecision) {
    match policy {
        PreflightPolicyDecision::Approve { .. } => {}
        PreflightPolicyDecision::Reject { reason } => {
            response.decision = "DENY".to_string();
            response.reason_code = "POLICY_VETO".to_string();
            response.detail = None;
            tracing::info!(target: "evidenceos.preflight.audit", detail=%reason, "policy veto detail");
        }
        PreflightPolicyDecision::Defer { reason } => {
            if response.decision != "DENY" {
                response.decision = "REQUIRE_HUMAN".to_string();
                response.reason_code = "POLICY_DEFER".to_string();
                response.detail = None;
                tracing::info!(target: "evidenceos.preflight.audit", detail=%reason, "policy defer detail");
            }
        }
    }
}

fn downgrade_params(
    tool_name: &str,
    params: &Map<String, Value>,
    high_risk_tools: &HashSet<String>,
) -> Option<Map<String, Value>> {
    if !high_risk_tools.contains(tool_name) {
        return Some(params.clone());
    }
    if tool_name == "exec" || tool_name == "shell.exec" {
        let mut rewritten = Map::new();
        rewritten.insert("command".to_string(), Value::String(String::new()));
        rewritten.insert("dry_run".to_string(), Value::Bool(true));
        return Some(rewritten);
    }
    None
}

#[allow(clippy::result_large_err)]
fn validate_ascii_printable_len(
    value: &str,
    min: usize,
    max: usize,
    field: &str,
) -> Result<(), HttpErr> {
    if value.len() < min || value.len() > max {
        return Err(HttpErr::invalid_argument(
            &format!("{field} must be between {min} and {max} chars"),
            "invalid_length",
        ));
    }
    if !value.chars().all(|c| c.is_ascii() && !c.is_ascii_control()) {
        return Err(HttpErr::invalid_argument(
            &format!("{field} must be ASCII printable"),
            "invalid_chars",
        ));
    }
    Ok(())
}

#[allow(clippy::result_large_err)]
fn validate_authorization(headers: &HeaderMap, cfg: &DaemonConfig) -> Result<(), HttpErr> {
    let Some(token) = cfg.preflight_require_bearer_token.as_ref() else {
        return Ok(());
    };
    let Some(value) = headers.get(AUTHORIZATION) else {
        return Err(HttpErr::unauthorized());
    };
    let parsed = value.to_str().map_err(|_| HttpErr::unauthorized())?;
    let expected = format!("Bearer {token}");
    if parsed != expected {
        return Err(HttpErr::unauthorized());
    }
    Ok(())
}

#[allow(clippy::result_large_err)]
fn validate_request_id(headers: &HeaderMap) -> Result<String, HttpErr> {
    let Some(value) = headers
        .get("x-request-id")
        .or_else(|| headers.get("x-evidenceos-request-id"))
    else {
        return Err(HttpErr::invalid_argument(
            "missing x-request-id or x-evidenceos-request-id header",
            "missing_request_id",
        ));
    };
    let request_id = value
        .to_str()
        .map_err(|_| HttpErr::invalid_argument("invalid x-request-id", "invalid_request_id"))?;
    if request_id.is_empty() || request_id.len() > 128 {
        return Err(HttpErr::invalid_argument(
            "invalid x-request-id",
            "invalid_request_id",
        ));
    }
    if request_id
        .bytes()
        .any(|b| !(0x21..=0x7e).contains(&b) || b == b':')
    {
        return Err(HttpErr::invalid_argument(
            "invalid x-request-id",
            "invalid_request_id",
        ));
    }
    Ok(request_id.to_string())
}

fn principal_id_from_auth(headers: &HeaderMap) -> String {
    if let Some(v) = headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok()) {
        if let Some(token) = v.strip_prefix("Bearer ") {
            return format!("bearer:{}", hex::encode(sha256_bytes(token.as_bytes())));
        }
    }
    if let Some(v) = headers
        .get("x-evidenceos-signature")
        .and_then(|v| v.to_str().ok())
    {
        return format!("hmac:{}", hex::encode(sha256_bytes(v.as_bytes())));
    }
    if let Some(v) = headers
        .get("x-client-cert-fp")
        .and_then(|v| v.to_str().ok())
    {
        return format!("mtls:{}", hex::encode(sha256_bytes(v.as_bytes())));
    }
    "anonymous".to_string()
}

fn sha256_bytes(payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(payload);
    hasher.finalize().into()
}

#[allow(clippy::result_large_err)]
fn enforce_rate_limit(state: &HttpPreflightState) -> Result<(), HttpErr> {
    let mut guard = state.rate_state.lock();
    if guard.started_at.elapsed() >= std::time::Duration::from_secs(1) {
        guard.started_at = Instant::now();
        guard.count = 0;
    }
    if guard.count >= state.cfg.preflight_rate_limit_rps {
        return Err(HttpErr::too_many_requests());
    }
    guard.count = guard.count.saturating_add(1);
    Ok(())
}

pub fn build_state(
    cfg: DaemonConfig,
    telemetry: Arc<Telemetry>,
    probe: Arc<Mutex<ProbeDetector>>,
    policy_oracles: Arc<Vec<PolicyOracleEngine>>,
) -> HttpPreflightState {
    let high_risk_tools = cfg
        .preflight_high_risk_tools
        .iter()
        .cloned()
        .collect::<HashSet<_>>();
    HttpPreflightState {
        hard_freeze_ops: crate::probe::ProbeConfig::from_env().freeze_total_requests,
        cfg,
        telemetry,
        probe,
        policy_oracles,
        clock: Arc::new(SystemClock),
        rate_state: Arc::new(Mutex::new(RateLimitState::default())),
        high_risk_tools: Arc::new(high_risk_tools),
        postflight_etl_path: PathBuf::from("artifacts/postflight.etl.ndjson"),
    }
}

pub async fn bind_listener(addr: &str) -> Result<tokio::net::TcpListener, std::io::Error> {
    let socket: SocketAddr = match addr.parse() {
        Ok(v) => v,
        Err(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid preflight listen address",
            ))
        }
    };
    tokio::net::TcpListener::bind(socket).await
}

fn maybe_auditor_detail(headers: &HeaderMap, detail: &str) -> Option<String> {
    if headers
        .get("x-evidenceos-role")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("auditor"))
        .unwrap_or(false)
    {
        Some(detail.to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::ProbeConfig;
    use axum::http::header::{HeaderName, HeaderValue, AUTHORIZATION};
    use serde_json::json;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct FixedClock {
        now: AtomicU64,
    }

    impl FixedClock {
        fn new(initial: u64) -> Self {
            Self {
                now: AtomicU64::new(initial),
            }
        }

        fn set(&self, value: u64) {
            self.now.store(value, Ordering::Relaxed);
        }
    }

    impl ProbeClock for FixedClock {
        fn now_ms(&self) -> u64 {
            self.now.load(Ordering::Relaxed)
        }
    }

    fn test_state(clock: Arc<dyn ProbeClock>) -> HttpPreflightState {
        let cfg = DaemonConfig {
            preflight_require_bearer_token: Some("token".to_string()),
            preflight_high_risk_tools: vec!["shell.exec".to_string()],
            ..DaemonConfig::default()
        };

        HttpPreflightState {
            cfg,
            telemetry: Arc::new(Telemetry::new().expect("telemetry")),
            probe: Arc::new(Mutex::new(ProbeDetector::new(ProbeConfig {
                freeze_total_requests: 99,
                ..ProbeConfig::default()
            }))),
            policy_oracles: Arc::new(Vec::new()),
            hard_freeze_ops: 3,
            clock,
            rate_state: Arc::new(Mutex::new(RateLimitState::default())),
            high_risk_tools: Arc::new(HashSet::from(["shell.exec".to_string()])),
            postflight_etl_path: PathBuf::from("artifacts/postflight.etl.ndjson"),
        }
    }

    fn test_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer token"));
        headers.insert(
            HeaderName::from_static("x-request-id"),
            HeaderValue::from_static("req-1"),
        );
        headers
    }

    #[tokio::test]
    async fn budget_remaining_is_monotonic_per_operation() {
        let clock_impl = Arc::new(FixedClock::new(1));
        let state = test_state(clock_impl.clone());
        let headers = test_headers();

        for (idx, expected_remaining) in [2_u64, 1, 0].into_iter().enumerate() {
            clock_impl.set((idx + 1) as u64);
            let body = json!({
                "toolName": "lowrisk.read",
                "params": {"k": idx},
                "sessionId": "session-1",
                "agentId": "agent-1"
            })
            .to_string();
            let response = preflight_tool_call_impl(&state, &headers, body.as_bytes())
                .await
                .expect("preflight response");
            let budget = response.budgetDelta.expect("budget present");
            assert_eq!(budget.remaining, expected_remaining);
        }

        clock_impl.set(10);
        let body = json!({
            "toolName": "lowrisk.read",
            "params": {"k": 9},
            "sessionId": "session-1",
            "agentId": "agent-1"
        })
        .to_string();
        let response = preflight_tool_call_impl(&state, &headers, body.as_bytes())
            .await
            .expect("preflight response");
        assert_eq!(response.decision, "DENY");
        assert_eq!(response.reason_code, "PROBE_FREEZE");
        assert_eq!(response.budgetDelta.expect("budget present").remaining, 0);
    }

    #[tokio::test]
    async fn high_risk_requires_session_id() {
        let clock_impl = Arc::new(FixedClock::new(1));
        let state = test_state(clock_impl);
        let headers = test_headers();
        let body = json!({
            "toolName": "shell.exec",
            "params": {"command": "echo hi"},
            "agentId": "agent-1"
        })
        .to_string();

        let err = preflight_tool_call_impl(&state, &headers, body.as_bytes())
            .await
            .expect_err("missing session should fail");

        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.response.decision, "DENY");
        assert_eq!(err.response.reason_code, "SESSION_REQUIRED");
    }
}
