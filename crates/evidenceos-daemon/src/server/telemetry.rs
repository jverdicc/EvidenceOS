use super::*;

impl EvidenceOsService {
    pub(super) fn observe_probe(
        &self,
        principal_id: String,
        operation_id: String,
        topic_id: String,
        semantic_hash: String,
    ) -> Result<(), Status> {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|v| v.as_millis() as u64)
            .map_err(|_| Status::internal("system clock before unix epoch"))?;
        let (verdict, snapshot) = self.probe_detector.lock().observe(
            &ProbeObservation {
                principal_id: principal_id.clone(),
                operation_id: operation_id.clone(),
                topic_id: topic_id.clone(),
                semantic_hash,
            },
            now_ms,
        );
        self.telemetry
            .set_probe_risk_score(&operation_id, snapshot.total_requests_window as f64);
        match verdict {
            ProbeVerdict::Clean => Ok(()),
            ProbeVerdict::Throttle {
                reason,
                retry_after_ms,
            } => {
                tracing::warn!(target: "evidenceos.probe", reason=%reason, principal_id=%principal_id, operation_id=%operation_id, topic_id=%topic_id, retry_after_ms=retry_after_ms, "probe throttled");
                self.telemetry.record_probe_throttled(reason);
                self.telemetry.record_probe_suspected(reason);
                Err(Status::resource_exhausted(format!(
                    "PROBE_THROTTLED: {reason}; retry_after_ms={retry_after_ms}"
                )))
            }
            ProbeVerdict::Escalate { reason } => {
                tracing::warn!(target: "evidenceos.probe", reason=%reason, principal_id=%principal_id, operation_id=%operation_id, topic_id=%topic_id, "probe escalated");
                self.telemetry.record_probe_escalated(reason);
                self.telemetry.record_probe_suspected(reason);
                self.append_probe_event(
                    &operation_id,
                    &principal_id,
                    &topic_id,
                    reason,
                    "ESCALATE",
                )?;
                Ok(())
            }
            ProbeVerdict::Freeze { reason } => {
                tracing::error!(target: "evidenceos.probe", reason=%reason, principal_id=%principal_id, operation_id=%operation_id, topic_id=%topic_id, "probe frozen");
                self.telemetry.record_probe_frozen(reason);
                self.telemetry.record_probe_suspected(reason);
                self.append_probe_event(&operation_id, &principal_id, &topic_id, reason, "FREEZE")?;
                Err(Status::permission_denied(format!("PROBE_FROZEN: {reason}")))
            }
        }
    }

    pub(super) fn append_probe_event(
        &self,
        operation_id: &str,
        principal_id: &str,
        topic_id: &str,
        reason: &str,
        action: &str,
    ) -> Result<(), Status> {
        let entry = serde_json::to_vec(&json!({
            "kind": "probe_event",
            "operation_id": operation_id,
            "principal_hash": hex::encode(sha256_bytes(principal_id.as_bytes())),
            "topic_hash": hex::encode(sha256_bytes(topic_id.as_bytes())),
            "reason": reason,
            "action": action,
        }))
        .map_err(|_| Status::internal("probe event encoding failed"))?;
        self.state
            .etl
            .lock()
            .append(&entry)
            .map_err(|_| Status::internal("probe event append failed"))?;
        Ok(())
    }

    pub(super) fn append_reservation_expired_incident(
        &self,
        claim: &Claim,
        released_k_bits: f64,
        released_access_credit: f64,
    ) -> Result<(), Status> {
        let entry = serde_json::to_vec(&json!({
            "kind": "reservation_expired",
            "claim_id": hex::encode(claim.claim_id),
            "topic_id": hex::encode(claim.topic_id),
            "released_k_bits": released_k_bits,
            "released_access_credit": released_access_credit,
            "operation_id": claim.operation_id,
        }))
        .map_err(|_| Status::internal("reservation expired incident encoding failed"))?;
        self.state
            .etl
            .lock()
            .append(&entry)
            .map_err(|_| Status::internal("reservation expired incident append failed"))?;
        Ok(())
    }

    pub(super) fn append_canary_incident(
        &self,
        claim: &Claim,
        reason: &str,
        e_drift: f64,
        barrier: f64,
    ) -> Result<(), Status> {
        let entry = serde_json::to_vec(&json!({
            "kind": "canary_incident",
            "reason": reason,
            "claim_id": hex::encode(claim.claim_id),
            "claim_name": claim.claim_name,
            "holdout_ref": claim.holdout_ref,
            "e_drift": e_drift,
            "barrier": barrier,
            "operation_id": claim.operation_id,
        }))
        .map_err(|_| Status::internal("canary incident encoding failed"))?;
        self.state
            .etl
            .lock()
            .append(&entry)
            .map_err(|_| Status::internal("canary incident append failed"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn module_smoke_test() {
        assert_eq!(2 + 2, 4);
    }
}
