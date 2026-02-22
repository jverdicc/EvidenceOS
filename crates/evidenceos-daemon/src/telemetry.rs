use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::Arc;

use parking_lot::Mutex;
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Debug, Error)]
pub enum TelemetryError {
    #[error("metrics server failed: {0}")]
    Server(std::io::Error),
}

#[derive(Debug, Clone, Serialize)]
pub struct LifecycleEvent<'a> {
    pub claim_id: &'a str,
    pub topic_id: &'a str,
    pub operation_id: &'a str,
    pub lane: &'a str,
    pub delta_k_bits: f64,
    pub delta_w: f64,
    pub decision: Option<i32>,
    pub epoch: u64,
    pub from: &'a str,
    pub to: &'a str,
    pub trial_config_hash_hex: Option<&'a str>,
}

#[derive(Debug, Default)]
struct TelemetryState {
    oracle_calls_total: HashMap<(String, String), u64>,
    lane_escalations_total: HashMap<(String, String), u64>,
    rejects_total: HashMap<String, u64>,
    k_bits_remaining: HashMap<String, f64>,
    w_current: HashMap<String, f64>,
    frozen: HashMap<String, i64>,
    probe_suspected_total: HashMap<String, u64>,
    probe_throttled_total: HashMap<String, u64>,
    probe_escalated_total: HashMap<String, u64>,
    probe_frozen_total: HashMap<String, u64>,
    probe_risk_score: HashMap<String, f64>,
    preflight_requests_total: HashMap<(String, String), u64>,
    preflight_latency_ms_bucket: BTreeMap<u64, u64>,
    preflight_failures_total: HashMap<String, u64>,
    credit_burned_total: HashMap<String, u64>,
    credit_denied_total: HashMap<String, u64>,
}

#[derive(Debug, Clone, Default)]
pub struct Telemetry {
    state: Arc<Mutex<TelemetryState>>,
}

impl Telemetry {
    pub fn new() -> Result<Self, TelemetryError> {
        Ok(Self::default())
    }

    pub fn lifecycle_event(&self, event: &LifecycleEvent<'_>) {
        tracing::info!(target: "evidenceos.lifecycle", event = ?event, "claim lifecycle transition");
    }

    pub fn record_oracle_calls(&self, lane: &str, oracle: &str, calls: u64) {
        let mut guard = self.state.lock();
        let entry = guard
            .oracle_calls_total
            .entry((lane.to_string(), oracle.to_string()))
            .or_insert(0);
        *entry = entry.saturating_add(calls);
    }

    pub fn record_lane_escalation(&self, from: &str, to: &str) {
        let mut guard = self.state.lock();
        let entry = guard
            .lane_escalations_total
            .entry((from.to_string(), to.to_string()))
            .or_insert(0);
        *entry = entry.saturating_add(1);
    }

    pub fn record_reject(&self, reason: &str) {
        let mut guard = self.state.lock();
        let entry = guard.rejects_total.entry(reason.to_string()).or_insert(0);
        *entry = entry.saturating_add(1);
    }

    pub fn record_probe_suspected(&self, reason: &str) {
        let mut guard = self.state.lock();
        let entry = guard
            .probe_suspected_total
            .entry(reason.to_string())
            .or_insert(0);
        *entry = entry.saturating_add(1);
    }

    pub fn record_probe_throttled(&self, reason: &str) {
        let mut guard = self.state.lock();
        let entry = guard
            .probe_throttled_total
            .entry(reason.to_string())
            .or_insert(0);
        *entry = entry.saturating_add(1);
    }

    pub fn record_probe_escalated(&self, reason: &str) {
        let mut guard = self.state.lock();
        let entry = guard
            .probe_escalated_total
            .entry(reason.to_string())
            .or_insert(0);
        *entry = entry.saturating_add(1);
    }

    pub fn record_probe_frozen(&self, reason: &str) {
        let mut guard = self.state.lock();
        let entry = guard
            .probe_frozen_total
            .entry(reason.to_string())
            .or_insert(0);
        *entry = entry.saturating_add(1);
    }

    pub fn set_probe_risk_score(&self, operation_id: &str, score: f64) {
        let mut guard = self.state.lock();
        guard
            .probe_risk_score
            .insert(operation_id.to_string(), score);
    }

    pub fn update_operation_gauges(
        &self,
        operation_id: &str,
        k_bits_remaining: f64,
        w_current: f64,
        frozen: bool,
    ) {
        let mut guard = self.state.lock();
        guard
            .k_bits_remaining
            .insert(operation_id.to_string(), k_bits_remaining);
        guard.w_current.insert(operation_id.to_string(), w_current);
        guard
            .frozen
            .insert(operation_id.to_string(), if frozen { 1 } else { 0 });
    }

    pub fn record_preflight_request(&self, decision: &str, reason_code: &str) {
        let mut guard = self.state.lock();
        let entry = guard
            .preflight_requests_total
            .entry((decision.to_string(), reason_code.to_string()))
            .or_insert(0);
        *entry = entry.saturating_add(1);
    }

    pub fn record_preflight_latency_ms(&self, latency_ms: u64) {
        let mut guard = self.state.lock();
        let bucket = [1_u64, 5, 10, 25, 50, 100, 250, 500, 1000]
            .into_iter()
            .find(|bound| latency_ms <= *bound)
            .unwrap_or(u64::MAX);
        let entry = guard.preflight_latency_ms_bucket.entry(bucket).or_insert(0);
        *entry = entry.saturating_add(1);
    }

    pub fn record_preflight_failure(&self, kind: &str) {
        let mut guard = self.state.lock();
        let entry = guard
            .preflight_failures_total
            .entry(kind.to_string())
            .or_insert(0);
        *entry = entry.saturating_add(1);
    }

    pub fn record_credit_burned(&self, principal_id: &str, amount: u64) {
        let mut guard = self.state.lock();
        let entry = guard
            .credit_burned_total
            .entry(principal_id.to_string())
            .or_insert(0);
        *entry = entry.saturating_add(amount);
    }

    pub fn record_credit_denied(&self, principal_id: &str) {
        let mut guard = self.state.lock();
        let entry = guard
            .credit_denied_total
            .entry(principal_id.to_string())
            .or_insert(0);
        *entry = entry.saturating_add(1);
    }

    pub fn render(&self) -> String {
        let guard = self.state.lock();
        let mut out = String::new();
        out.push_str("# TYPE oracle_calls_total counter\n");
        for ((lane, oracle), value) in &guard.oracle_calls_total {
            let _ = writeln!(
                out,
                "oracle_calls_total{{lane=\"{}\",oracle=\"{}\"}} {}",
                lane, oracle, value
            );
        }
        out.push_str("# TYPE lane_escalations_total counter\n");
        for ((from, to), value) in &guard.lane_escalations_total {
            let _ = writeln!(
                out,
                "lane_escalations_total{{from=\"{}\",to=\"{}\"}} {}",
                from, to, value
            );
        }
        out.push_str("# TYPE rejects_total counter\n");
        for (reason, value) in &guard.rejects_total {
            let _ = writeln!(out, "rejects_total{{reason=\"{}\"}} {}", reason, value);
        }

        out.push_str("# TYPE probe_suspected_total counter\n");
        for (reason, value) in &guard.probe_suspected_total {
            let _ = writeln!(
                out,
                "probe_suspected_total{{reason=\"{}\"}} {}",
                reason, value
            );
        }
        out.push_str("# TYPE probe_throttled_total counter\n");
        for (reason, value) in &guard.probe_throttled_total {
            let _ = writeln!(
                out,
                "probe_throttled_total{{reason=\"{}\"}} {}",
                reason, value
            );
        }
        out.push_str("# TYPE probe_escalated_total counter\n");
        for (reason, value) in &guard.probe_escalated_total {
            let _ = writeln!(
                out,
                "probe_escalated_total{{reason=\"{}\"}} {}",
                reason, value
            );
        }
        out.push_str("# TYPE probe_frozen_total counter\n");
        for (reason, value) in &guard.probe_frozen_total {
            let _ = writeln!(out, "probe_frozen_total{{reason=\"{}\"}} {}", reason, value);
        }
        out.push_str("# TYPE probe_risk_score gauge\n");
        for (operation_id, value) in &guard.probe_risk_score {
            let _ = writeln!(
                out,
                "probe_risk_score{{operation_id=\"{}\"}} {}",
                operation_id, value
            );
        }
        out.push_str("# TYPE k_bits_remaining gauge\n");
        for (operation_id, value) in &guard.k_bits_remaining {
            let _ = writeln!(
                out,
                "k_bits_remaining{{operation_id=\"{}\"}} {}",
                operation_id, value
            );
        }
        out.push_str("# TYPE w_current gauge\n");
        for (operation_id, value) in &guard.w_current {
            let _ = writeln!(
                out,
                "w_current{{operation_id=\"{}\"}} {}",
                operation_id, value
            );
        }
        out.push_str("# TYPE frozen gauge\n");
        for (operation_id, value) in &guard.frozen {
            let _ = writeln!(out, "frozen{{operation_id=\"{}\"}} {}", operation_id, value);
        }
        out.push_str("# TYPE evidenceos_preflight_requests_total counter\n");
        for ((decision, reason_code), value) in &guard.preflight_requests_total {
            let _ = writeln!(
                out,
                "evidenceos_preflight_requests_total{{decision=\"{}\",reasonCode=\"{}\"}} {}",
                decision, reason_code, value
            );
        }
        out.push_str("# TYPE evidenceos_preflight_latency_ms_bucket counter\n");
        for (bucket, value) in &guard.preflight_latency_ms_bucket {
            let bucket_label = if *bucket == u64::MAX {
                "+Inf".to_string()
            } else {
                bucket.to_string()
            };
            let _ = writeln!(
                out,
                "evidenceos_preflight_latency_ms_bucket{{le=\"{}\"}} {}",
                bucket_label, value
            );
        }
        out.push_str("# TYPE evidenceos_preflight_failures_total counter\n");
        for (kind, value) in &guard.preflight_failures_total {
            let _ = writeln!(
                out,
                "evidenceos_preflight_failures_total{{kind=\"{}\"}} {}",
                kind, value
            );
        }
        out.push_str("# TYPE evidenceos_credit_burned_total counter\n");
        for (principal_id, value) in &guard.credit_burned_total {
            let _ = writeln!(
                out,
                "evidenceos_credit_burned_total{{principal_id=\"{}\"}} {}",
                principal_id, value
            );
        }
        out.push_str("# TYPE evidenceos_credit_denied_total counter\n");
        for (principal_id, value) in &guard.credit_denied_total {
            let _ = writeln!(
                out,
                "evidenceos_credit_denied_total{{principal_id=\"{}\"}} {}",
                principal_id, value
            );
        }
        out
    }

    pub async fn spawn_metrics_server(
        self: Arc<Self>,
        addr: SocketAddr,
    ) -> Result<tokio::task::JoinHandle<()>, TelemetryError> {
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(TelemetryError::Server)?;
        Ok(tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((mut socket, _)) => {
                        let telemetry = self.clone();
                        tokio::spawn(async move {
                            let mut buf = vec![0_u8; 2048];
                            match socket.read(&mut buf).await {
                                Ok(n) if n > 0 => {
                                    let req = String::from_utf8_lossy(&buf[..n]);
                                    let (status, body) = if req.starts_with("GET /metrics ") {
                                        ("200 OK", telemetry.render())
                                    } else {
                                        ("404 Not Found", "not found".to_string())
                                    };
                                    let response = format!(
                                        "HTTP/1.1 {status}\r\ncontent-type: text/plain; version=0.0.4\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                                        body.len(), body
                                    );
                                    let _ = socket.write_all(response.as_bytes()).await;
                                }
                                Ok(_) => {}
                                Err(err) => {
                                    tracing::warn!(error=%err, "metrics socket read failed");
                                }
                            }
                        });
                    }
                    Err(err) if err.kind() == ErrorKind::Interrupted => continue,
                    Err(err) => {
                        tracing::error!(error=%err, "metrics server accept failed");
                        break;
                    }
                }
            }
        }))
    }
}

pub fn derive_operation_id<I, K, V>(pairs: I) -> String
where
    I: IntoIterator<Item = (K, V)>,
    K: Into<String>,
    V: Into<String>,
{
    let canonical: BTreeMap<String, String> = pairs
        .into_iter()
        .map(|(k, v)| (k.into(), v.into()))
        .collect();
    let mut hasher = Sha256::new();
    for (key, value) in canonical {
        hasher.update(key.as_bytes());
        hasher.update(b"=");
        hasher.update(value.len().to_be_bytes());
        hasher.update(value.as_bytes());
        hasher.update(b";");
    }
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::derive_operation_id;

    #[test]
    fn operation_id_deterministic_across_input_order() {
        let a = derive_operation_id(vec![
            ("topic_id", "aa"),
            ("lineage_root", "bb"),
            ("action_class", "execute_claim_v2"),
            ("phys_signature_hash", "cc"),
        ]);
        let b = derive_operation_id(vec![
            ("phys_signature_hash", "cc"),
            ("action_class", "execute_claim_v2"),
            ("lineage_root", "bb"),
            ("topic_id", "aa"),
        ]);
        assert_eq!(a, b);
    }

    #[test]
    fn operation_id_changes_when_any_component_changes() {
        let base = derive_operation_id(vec![
            ("topic_id", "aa"),
            ("lineage_root", "bb"),
            ("action_class", "execute_claim_v2"),
            ("phys_signature_hash", "cc"),
        ]);
        let changed = derive_operation_id(vec![
            ("topic_id", "aa"),
            ("lineage_root", "bc"),
            ("action_class", "execute_claim_v2"),
            ("phys_signature_hash", "cc"),
        ]);
        assert_ne!(base, changed);
    }
}
