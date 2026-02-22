use super::*;

impl EvidenceOsService {
    pub(super) fn lane_name(lane: Lane) -> &'static str {
        match lane {
            Lane::Fast => "fast",
            Lane::Heavy => "heavy",
        }
    }

    pub(super) fn state_name(state: ClaimState) -> &'static str {
        match state {
            ClaimState::Uncommitted => "UNCOMMITTED",
            ClaimState::Committed => "COMMITTED",
            ClaimState::Sealed => "SEALED",
            ClaimState::Executing => "EXECUTING",
            ClaimState::Settled => "SETTLED",
            ClaimState::Certified => "CERTIFIED",
            ClaimState::Revoked => "REVOKED",
            ClaimState::Tainted => "TAINTED",
            ClaimState::Stale => "STALE",
            ClaimState::Frozen => "FROZEN",
        }
    }

    pub(super) fn transition_claim_internal(
        claim: &mut Claim,
        to: ClaimState,
    ) -> Result<(), Status> {
        if claim.state == to {
            return Ok(());
        }
        if claim.state == ClaimState::Uncommitted && to == ClaimState::Committed {
            claim.state = ClaimState::Committed;
            return Ok(());
        }
        if claim.state == ClaimState::Settled && to == ClaimState::Frozen {
            claim.state = ClaimState::Frozen;
            return Ok(());
        }
        if to == ClaimState::Committed {
            return Err(Status::failed_precondition(
                "invalid claim state transition",
            ));
        }
        let from_core = if claim.state == ClaimState::Committed {
            CoreClaimState::Uncommitted
        } else {
            claim
                .state
                .as_core()
                .ok_or_else(|| Status::failed_precondition("invalid claim state transition"))?
        };
        let target_core = to
            .as_core()
            .ok_or_else(|| Status::failed_precondition("invalid claim state transition"))?;
        from_core
            .transition(target_core)
            .map_err(|_| Status::failed_precondition("invalid claim state transition"))?;
        claim.state = to;
        Ok(())
    }

    pub(super) fn transition_claim(
        &self,
        claim: &mut Claim,
        to: ClaimState,
        delta_k_bits: f64,
        delta_w: f64,
        decision: Option<i32>,
    ) -> Result<(), Status> {
        let from = claim.state;
        Self::transition_claim_internal(claim, to)?;
        let claim_id = hex::encode(claim.claim_id);
        let topic_id = hex::encode(claim.topic_id);
        let trial_config_hash_hex = self.trial_config_hash.map(hex::encode);
        let event = LifecycleEvent {
            claim_id: &claim_id,
            topic_id: &topic_id,
            operation_id: &claim.operation_id,
            lane: Self::lane_name(claim.lane),
            delta_k_bits,
            delta_w,
            decision,
            epoch: claim.epoch_counter,
            from: Self::state_name(from),
            to: Self::state_name(to),
            trial_config_hash_hex: trial_config_hash_hex.as_deref(),
        };
        self.telemetry.lifecycle_event(&event);
        let remaining = claim.ledger.k_bits_budget().map_or(0.0, |budget| {
            (budget - claim.ledger.k_bits_total()).max(0.0)
        });
        self.telemetry.update_operation_gauges(
            &claim.operation_id,
            remaining,
            claim.ledger.wealth(),
            claim.ledger.is_frozen() || claim.state == ClaimState::Frozen,
        );
        Ok(())
    }

    pub(super) fn maybe_mark_stale(claim: &mut Claim, current_epoch: u64) -> Result<(), Status> {
        let pins = match claim.oracle_pins.as_ref() {
            Some(p) => p,
            None => return Ok(()),
        };
        if claim.state != ClaimState::Sealed {
            return Ok(());
        }
        if current_epoch.saturating_sub(pins.pinned_epoch) > pins.ttl_epochs {
            Self::transition_claim_internal(claim, ClaimState::Stale)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claim_with_state(state: ClaimState) -> Claim {
        let mut claim = dummy_claim([9u8; 32], None);
        claim.state = state;
        claim
    }

    #[test]
    fn transition_uncommitted_to_committed_allowed() {
        let mut claim = claim_with_state(ClaimState::Uncommitted);
        EvidenceOsService::transition_claim_internal(&mut claim, ClaimState::Committed)
            .expect("ok");
        assert_eq!(claim.state, ClaimState::Committed);
    }

    #[test]
    fn transition_committed_to_sealed_allowed() {
        let mut claim = claim_with_state(ClaimState::Committed);
        EvidenceOsService::transition_claim_internal(&mut claim, ClaimState::Sealed).expect("ok");
        assert_eq!(claim.state, ClaimState::Sealed);
    }

    #[test]
    fn transition_sealed_to_executing_allowed() {
        let mut claim = claim_with_state(ClaimState::Sealed);
        EvidenceOsService::transition_claim_internal(&mut claim, ClaimState::Executing)
            .expect("ok");
        assert_eq!(claim.state, ClaimState::Executing);
    }

    #[test]
    fn transition_executing_to_settled_allowed() {
        let mut claim = claim_with_state(ClaimState::Executing);
        EvidenceOsService::transition_claim_internal(&mut claim, ClaimState::Settled).expect("ok");
        assert_eq!(claim.state, ClaimState::Settled);
    }

    #[test]
    fn transition_settled_to_certified_allowed() {
        let mut claim = claim_with_state(ClaimState::Settled);
        EvidenceOsService::transition_claim_internal(&mut claim, ClaimState::Certified)
            .expect("ok");
        assert_eq!(claim.state, ClaimState::Certified);
    }

    #[test]
    fn transition_settled_to_frozen_allowed() {
        let mut claim = claim_with_state(ClaimState::Settled);
        EvidenceOsService::transition_claim_internal(&mut claim, ClaimState::Frozen).expect("ok");
        assert_eq!(claim.state, ClaimState::Frozen);
    }

    #[test]
    fn transition_sealed_to_stale_allowed() {
        let mut claim = claim_with_state(ClaimState::Sealed);
        EvidenceOsService::transition_claim_internal(&mut claim, ClaimState::Stale).expect("ok");
        assert_eq!(claim.state, ClaimState::Stale);
    }

    #[test]
    fn transition_invalid_rejects() {
        let mut claim = claim_with_state(ClaimState::Uncommitted);
        let err = EvidenceOsService::transition_claim_internal(&mut claim, ClaimState::Executing)
            .expect_err("invalid");
        assert_eq!(err.code(), Code::FailedPrecondition);
    }
}
