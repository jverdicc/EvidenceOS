use super::*;

impl EvidenceOsService {
    pub(super) fn oracle_ttl_for_claim(&self, claim: &Claim) -> u64 {
        self.state
            .operator_config
            .lock()
            .oracle_ttl_epochs
            .get(&claim.oracle_id)
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
        claim.dependency_capsule_hashes = claim.dependency_items.iter().map(hex::encode).collect();

        let dependency_merkle_root = dependency_merkle_root(&claim.dependency_items);
        match claim.dependency_merkle_root {
            Some(committed_root) => {
                if committed_root != dependency_merkle_root {
                    return Err(Status::failed_precondition(
                        "dependency merkle root mismatch",
                    ));
                }
            }
            None => {
                if !claim.dependency_items.is_empty() {
                    return Err(Status::failed_precondition(
                        "dependency items require create-time dependency_merkle_root",
                    ));
                }
            }
        }
        claim.lineage_root_hash = dependency_merkle_root;

        let wasm_hash = sha256_bytes(&claim.wasm_module);
        let artifacts_hash = artifacts_commitment(&claim.artifacts);
        let holdout_ref_hash = sha256_bytes(claim.holdout_ref.as_bytes());

        let bit_width = claim.oracle_resolution.bit_width as u32;
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
            .clone()
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
        let trial_schema_version = claim.trial_assignment.as_ref().map_or(
            TRIAL_COMMITMENT_SCHEMA_VERSION_CURRENT,
            |assignment| {
                u8::try_from(assignment.schema_version)
                    .unwrap_or(TRIAL_COMMITMENT_SCHEMA_VERSION_CURRENT)
            },
        );
        let trial_commitment_hash =
            trial_commitment_hash(claim.trial_assignment.as_ref(), trial_schema_version);

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
    use tempfile::TempDir;

    use super::*;

    fn test_service() -> EvidenceOsService {
        let dir = TempDir::new().expect("tmp");
        let telemetry = Arc::new(Telemetry::new().expect("telemetry"));
        EvidenceOsService::build_with_options(dir.path().to_str().expect("utf8"), true, telemetry)
            .expect("service")
    }

    fn committed_claim(oracle_id: &str, claim_name: &str) -> Claim {
        Claim {
            claim_id: [1; 32],
            topic_id: [2; 32],
            holdout_handle_id: [3; 32],
            holdout_ref: "holdout".to_string(),
            epoch_config_ref: "epoch-a".to_string(),
            holdout_len: 4,
            metadata_locked: false,
            claim_name: claim_name.to_string(),
            oracle_id: oracle_id.to_string(),
            nullspec_id: String::new(),
            output_schema_id: "legacy/v1".to_string(),
            phys_hir_hash: [0; 32],
            semantic_hash: [0; 32],
            topic_oracle_receipt: None,
            output_schema_id_hash: [0; 32],
            holdout_handle_hash: [0; 32],
            lineage_root_hash: [0; 32],
            disagreement_score: 0,
            semantic_physhir_distance_bits: 0,
            escalate_to_heavy: false,
            epoch_size: 10,
            epoch_counter: 0,
            dlc_fuel_accumulated: 0,
            pln_config: None,
            oracle_num_symbols: 4,
            oracle_resolution: OracleResolution::new(4, 0.0).expect("resolution"),
            state: ClaimState::Committed,
            artifacts: vec![([7; 32], "artifact-a".to_string())],
            dependency_capsule_hashes: Vec::new(),
            dependency_items: Vec::new(),
            dependency_merkle_root: None,
            wasm_module: vec![1, 2, 3],
            aspec_rejection: None,
            aspec_report_summary: None,
            lane: Lane::Fast,
            heavy_lane_diversion_recorded: false,
            ledger: ConservationLedger::new(0.1).expect("ledger"),
            last_decision: None,
            last_capsule_hash: None,
            capsule_bytes: None,
            etl_index: None,
            oracle_pins: None,
            freeze_preimage: None,
            operation_id: "op".to_string(),
            owner_principal_id: "test-owner".to_string(),
            created_at_unix_ms: 1,
            trial_assignment: None,
            trial_commitment_hash: [0; 32],
            execution_nonce: 0,
            holdout_pool_scope: HoldoutPoolScope::Global,
            reserved_k_bits: 0.0,
            reserved_access_credit: 0.0,
            reserved_expires_at_unix_ms: 0,
        }
    }

    #[test]
    fn freeze_claim_gates_uses_oracle_id_ttl_override() {
        let svc = test_service();
        let oracle_id = "oracle-alpha";
        let ttl = 9;
        svc.state
            .operator_config
            .lock()
            .oracle_ttl_epochs
            .insert(oracle_id.to_string(), ttl);

        let mut claim = committed_claim(oracle_id, "different-claim-name");
        svc.freeze_claim_gates(&mut claim).expect("freeze");

        assert_eq!(claim.oracle_resolution.ttl_epochs, Some(ttl));
        let oracle_pins = claim.oracle_pins.expect("pins");
        assert_eq!(oracle_pins.ttl_epochs, ttl);
    }

    #[test]
    fn freeze_claim_gates_uses_default_ttl_for_unknown_oracle_id() {
        let svc = test_service();
        svc.state
            .operator_config
            .lock()
            .oracle_ttl_epochs
            .insert("some-other-oracle".to_string(), 7);

        let mut claim = committed_claim("oracle-missing", "claim-without-override");
        svc.freeze_claim_gates(&mut claim).expect("freeze");

        assert_eq!(claim.oracle_resolution.ttl_epochs, Some(1));
        let oracle_pins = claim.oracle_pins.expect("pins");
        assert_eq!(oracle_pins.ttl_epochs, 1);
    }

    #[test]
    fn freeze_claim_gates_preserves_minimal_oracle_bit_width_in_pins() {
        let svc = test_service();
        let mut claim = committed_claim("oracle-alpha", "claim-bit-width-3-symbols");
        claim.oracle_num_symbols = 3;
        claim.oracle_resolution = OracleResolution::new(3, 0.0).expect("resolution");

        svc.freeze_claim_gates(&mut claim).expect("freeze");

        assert_eq!(claim.oracle_resolution.bit_width, 2);
        let pins = claim.oracle_pins.expect("pins");
        assert_eq!(pins.bit_width, 2);

        let freeze_preimage = claim.freeze_preimage.expect("freeze preimage");
        let mut preimage_payload = Vec::new();
        preimage_payload.extend_from_slice(&freeze_preimage.artifacts_hash);
        preimage_payload.extend_from_slice(&freeze_preimage.wasm_hash);
        preimage_payload.extend_from_slice(&freeze_preimage.dependency_merkle_root);
        preimage_payload.extend_from_slice(&freeze_preimage.holdout_ref_hash);
        preimage_payload.extend_from_slice(&freeze_preimage.oracle_hash);
        preimage_payload.extend_from_slice(&freeze_preimage.trial_commitment_hash);

        assert_eq!(
            freeze_preimage.sealed_preimage_hash,
            sha256_bytes(&preimage_payload)
        );
    }

    #[test]
    fn module_smoke_test() {
        assert_eq!(2 + 2, 4);
    }
}
