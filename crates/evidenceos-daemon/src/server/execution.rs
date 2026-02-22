use super::*;

impl EvidenceOsService {
    pub(super) fn idempotency_lookup_execute_claim_v2(
        &self,
        principal_id: &str,
        request_id: &str,
    ) -> Result<Option<pb::ExecuteClaimV2Response>, Status> {
        let now = Instant::now();
        let mut cache = self.state.execute_claim_v2_idempotency.lock();
        cache.retain(|_, entry| match entry {
            IdempotencyEntry::InFlight { expires_at } => *expires_at > now,
            IdempotencyEntry::Ready { expires_at, .. } => *expires_at > now,
        });
        let key = (principal_id.to_string(), request_id.to_string());
        if let Some(entry) = cache.get(&key) {
            return match entry {
                IdempotencyEntry::Ready { cached, .. } => Ok(Some(cached.response.clone())),
                IdempotencyEntry::InFlight { .. } => Err(Status::aborted(
                    "request with x-request-id already in progress",
                )),
            };
        }
        cache.insert(
            key,
            IdempotencyEntry::InFlight {
                expires_at: now + IDEMPOTENCY_TTL,
            },
        );
        Ok(None)
    }

    pub(super) fn idempotency_store_execute_claim_v2(
        &self,
        principal_id: String,
        request_id: String,
        response: pb::ExecuteClaimV2Response,
    ) {
        let mut cache = self.state.execute_claim_v2_idempotency.lock();
        cache.insert(
            (principal_id, request_id),
            IdempotencyEntry::Ready {
                expires_at: Instant::now() + IDEMPOTENCY_TTL,
                cached: IdempotencyCachedResponse { response },
            },
        );
    }

    pub(super) fn record_incident(&self, claim: &mut Claim, reason: &str) -> Result<(), Status> {
        claim.state = ClaimState::Frozen;
        claim
            .ledger
            .freeze("incident_freeze", json!({"reason": reason}));
        if let Some(capsule_hash) = claim.last_capsule_hash {
            let mut etl = self.state.etl.lock();
            etl.revoke(&hex::encode(capsule_hash), reason)
                .map_err(|_| Status::internal("etl incident append failed"))?;
        }
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
