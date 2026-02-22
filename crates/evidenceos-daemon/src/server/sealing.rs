use super::*;

impl EvidenceOsService {
    pub(super) fn oracle_ttl_for_claim(&self, claim: &Claim) -> u64 {
        self.state
            .operator_config
            .lock()
            .oracle_ttl_epochs
            .get(&claim.claim_name)
            .copied()
            .unwrap_or(1)
            .max(1)
    }

    pub(super) fn current_epoch_for_claim(&self, claim: &Claim) -> Result<u64, Status> {
        let forced = self.state.operator_config.lock().forced_epoch;
        if let Some(epoch) = forced {
            return Ok(epoch);
        }
        current_logical_epoch(claim)
    }

    pub(super) fn freeze_claim_gates(&self, claim: &mut Claim) -> Result<(), Status> {
        if claim.freeze_preimage.is_some() && claim.state == ClaimState::Sealed {
            return Ok(());
        }
        if claim.state != ClaimState::Committed && claim.state != ClaimState::Stale {
            return Err(Status::failed_precondition(
                "claim must be COMMITTED or STALE to freeze gates",
            ));
        }
        if claim.artifacts.is_empty() {
            return Err(Status::failed_precondition(
                "artifacts must be committed before freeze",
            ));
        }
        if claim.wasm_module.is_empty() {
            return Err(Status::failed_precondition(
                "wasm bytes must be committed before freeze",
            ));
        }
        if claim.aspec_rejection.is_some() {
            return Err(Status::failed_precondition("ASPEC report must be accepted"));
        }
        if claim.lane == Lane::Heavy && !claim.heavy_lane_diversion_recorded {
            return Err(Status::failed_precondition(
                "heavy lane diversion must be recorded before freeze",
            ));
        }

        claim
            .artifacts
            .sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
        if claim.dependency_items.len() > MAX_DEPENDENCY_ITEMS {
            return Err(Status::failed_precondition(
                "dependency list exceeds allowed size",
            ));
        }
        claim.dependency_items.sort();

        let dependency_merkle_root = dependency_merkle_root(&claim.dependency_items);
        claim.dependency_merkle_root = Some(dependency_merkle_root);

        let wasm_hash = sha256_bytes(&claim.wasm_module);
        let artifacts_hash = artifacts_commitment(&claim.artifacts);
        let holdout_ref_hash = sha256_bytes(claim.holdout_ref.as_bytes());

        let bit_width = canonical_len_for_symbols(claim.oracle_num_symbols)? as u32 * 8;
        let pinned_epoch = self.current_epoch_for_claim(claim)?;
        let ttl_epochs = self.oracle_ttl_for_claim(claim);
        let oracle_id = claim.oracle_id.clone();
        let calibration_hash = {
            let operator_config = self.state.operator_config.lock();
            match operator_config.oracle_calibration_hash.get(&oracle_id) {
                Some(v) => decode_hex_hash32(v, "calibration_manifest_hash_hex")?,
                None => {
                    if self.enforce_operator_provenance {
                        return Err(Status::failed_precondition(
                            "missing oracle calibration manifest hash",
                        ));
                    }
                    claim.oracle_resolution.calibration_manifest_hash
                }
            }
        };
        claim.oracle_resolution = claim
            .oracle_resolution
            .with_calibration(calibration_hash, pinned_epoch);
        claim.oracle_resolution.ttl_epochs = Some(ttl_epochs);
        let resolution_hash = oracle_resolution_hash(&claim.oracle_resolution)?;
        let oracle_pins = OraclePins {
            codec_hash: sha256_bytes(b"evidenceos.oracle.codec.v1"),
            bit_width,
            ttl_epochs,
            pinned_epoch,
            oracle_resolution_hash: resolution_hash,
        };
        let oracle_hash = oracle_pins_hash(&oracle_pins);
        let trial_commitment_hash = trial_commitment_hash(claim.trial_assignment.as_ref());

        let mut preimage_payload = Vec::new();
        preimage_payload.extend_from_slice(&artifacts_hash);
        preimage_payload.extend_from_slice(&wasm_hash);
        preimage_payload.extend_from_slice(&dependency_merkle_root);
        preimage_payload.extend_from_slice(&holdout_ref_hash);
        preimage_payload.extend_from_slice(&oracle_hash);
        preimage_payload.extend_from_slice(&trial_commitment_hash);
        let sealed_preimage_hash = sha256_bytes(&preimage_payload);

        claim.oracle_pins = Some(oracle_pins);
        claim.freeze_preimage = Some(FreezePreimage {
            artifacts_hash,
            wasm_hash,
            dependency_merkle_root,
            holdout_ref_hash,
            oracle_hash,
            trial_commitment_hash,
            sealed_preimage_hash,
        });
        claim.trial_commitment_hash = trial_commitment_hash;
        claim.metadata_locked = true;
        Self::transition_claim_internal(claim, ClaimState::Sealed)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn module_smoke_test() {
        assert_eq!(2 + 2, 4);
    }
}
