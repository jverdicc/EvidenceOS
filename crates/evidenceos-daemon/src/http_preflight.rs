use std::collections::HashSet;
use std::net::SocketAddr;
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
use serde_json::{Map, Value};
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
    pub sessionId: Option<String>,
    pub agentId: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[allow(non_snake_case)]
pub struct PreflightToolCallResponse {
    pub decision: String,
    pub reason_code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rewrittenParams: Option<Map<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budgetDelta: Option<BudgetDelta>,
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

#[derive(Debug)]
pub struct HttpErr {
    pub(crate) status: StatusCode,
    pub(crate) kind: &'static str,
    pub(crate) response: PreflightToolCallResponse,
    _source: EvidenceOSError,
}

impl HttpErr {
    fn invalid_argument(detail: &str, kind: &'static str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            kind,
            response: PreflightToolCallResponse {
                decision: "DENY".to_string(),
                reason_code: PublicErrorCode::InvalidInput.as_str().to_string(),
                detail: None,
                rewrittenParams: None,
                budgetDelta: None,
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

    let params_canonical = canonical_json(&req.params)
        .map_err(|_| HttpErr::invalid_argument("invalid params object", "params_canonical"))?;
    let params_hash = stable_params_hash(&req.params)
        .map_err(|_| HttpErr::invalid_argument("invalid params object", "params_hash"))?;

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
    let remaining = hard_freeze_ops.saturating_sub(snapshot.total_requests_window) as u64;
    let budget = Some(BudgetDelta {
        spent: 1,
        remaining,
    });
    match verdict {
        ProbeVerdict::Clean => PreflightToolCallResponse {
            decision: "ALLOW".to_string(),
            reason_code: "PROBE_CLEAN".to_string(),
            detail: None,
            rewrittenParams: None,
            budgetDelta: budget,
        },
        ProbeVerdict::Throttle { reason: _, .. } => PreflightToolCallResponse {
            decision: "DOWNGRADE".to_string(),
            reason_code: "PROBE_THROTTLE".to_string(),
            detail: None,
            rewrittenParams: None,
            budgetDelta: budget,
        },
        ProbeVerdict::Escalate { reason: _ } => PreflightToolCallResponse {
            decision: "REQUIRE_HUMAN".to_string(),
            reason_code: "PROBE_ESCALATE".to_string(),
            detail: None,
            rewrittenParams: None,
            budgetDelta: budget,
        },
        ProbeVerdict::Freeze { reason: _ } => PreflightToolCallResponse {
            decision: "DENY".to_string(),
            reason_code: "PROBE_FREEZE".to_string(),
            detail: None,
            rewrittenParams: None,
            budgetDelta: budget,
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
    let Some(value) = headers.get("x-request-id") else {
        return Err(HttpErr::invalid_argument(
            "missing x-request-id header",
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
