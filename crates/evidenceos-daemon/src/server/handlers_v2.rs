use super::*;

#[tonic::async_trait]
impl EvidenceOsV2 for EvidenceOsService {
    type WatchRevocationsStream = Pin<
        Box<
            dyn tokio_stream::Stream<Item = Result<pb::WatchRevocationsResponse, Status>>
                + Send
                + 'static,
        >,
    >;

    async fn health(
        &self,
        _request: Request<pb::HealthRequest>,
    ) -> Result<Response<pb::HealthResponse>, Status> {
        Ok(Response::new(pb::HealthResponse {
            status: "SERVING".to_string(),
        }))
    }

    async fn get_server_info(
        &self,
        _request: Request<pb::GetServerInfoRequest>,
    ) -> Result<Response<pb::GetServerInfoResponse>, Status> {
        Ok(Response::new(pb::GetServerInfoResponse {
            protocol_semver: evidenceos_protocol::PROTOCOL_SEMVER.to_string(),
            proto_hash: evidenceos_protocol::PROTO_SHA256.to_string(),
            build_git_commit: BUILD_GIT_COMMIT.to_string(),
            build_time_utc: BUILD_TIME_UTC.to_string(),
            daemon_version: env!("CARGO_PKG_VERSION").to_string(),
            feature_flags: Some(self.protocol_feature_flags()),
        }))
    }

    async fn create_claim(
        &self,
        request: Request<pb::CreateClaimRequest>,
    ) -> Result<Response<pb::CreateClaimResponse>, Status> {
        let caller = Self::caller_identity(request.metadata());
        let req = request.into_inner();
        if req.epoch_size == 0 {
            return Err(Status::invalid_argument("epoch_size must be > 0"));
        }
        let topic_id = parse_hash32(&req.topic_id, "topic_id")?;
        let holdout_handle_id = parse_hash32(&req.holdout_handle_id, "holdout_handle_id")?;
        let phys_hir_hash = parse_hash32(&req.phys_hir_hash, "phys_hir_hash")?;
        let _ = canonical_len_for_symbols(req.oracle_num_symbols)?;
        let access_credit = req.access_credit as f64;
        Self::validate_budget_value(access_credit, "access_credit")?;
        self.admission_provider
            .admit(&caller.principal_id, req.access_credit)?;
        let oracle_resolution = OracleResolution::new(req.oracle_num_symbols, 0.0)
            .map_err(|_| Status::invalid_argument("oracle_num_symbols must be >= 2"))?;
        let ledger = ConservationLedger::new(req.alpha)
            .map_err(|_| Status::invalid_argument("alpha must be in (0,1)"))
            .map(|l| l.with_budgets(Some(access_credit), Some(access_credit)))?;

        let mut id_payload = Vec::new();
        id_payload.extend_from_slice(&topic_id);
        id_payload.extend_from_slice(&holdout_handle_id);
        id_payload.extend_from_slice(&phys_hir_hash);
        id_payload.extend_from_slice(&req.epoch_size.to_be_bytes());
        id_payload.extend_from_slice(&oracle_resolution.num_symbols.to_be_bytes());
        let claim_id = sha256_domain(DOMAIN_CLAIM_ID, &id_payload);

        if let Some(existing) = self.state.claims.lock().get(&claim_id).cloned() {
            return Ok(Response::new(pb::CreateClaimResponse {
                claim_id: claim_id.to_vec(),
                state: existing.state.to_proto(),
            }));
        }

        let operation_id = build_operation_id(
            topic_id,
            None,
            claim_id,
            "create_claim_v1",
            Some(phys_hir_hash),
        );
        let trial_nonce = generate_trial_nonce()?;
        let trial_assignment = self.trial_router.assign(
            trial_nonce,
            &StratumKey::from_baseline(BaselineCovariates {
                lane: "fast".to_string(),
                holdout_ref: hex::encode(holdout_handle_id),
                oracle_id: "builtin.accuracy".to_string(),
                nullspec_id: String::new(),
            }),
        )?;
        let created_at_unix_ms = current_time_unix_ms()?;
        let claim = Claim {
            claim_id,
            topic_id,
            dependency_merkle_root: None,
            holdout_handle_id,
            holdout_ref: hex::encode(holdout_handle_id),
            epoch_config_ref: "legacy-v1".to_string(),
            holdout_len: req.epoch_size,
            metadata_locked: false,
            claim_name: "legacy-v1".to_string(),
            oracle_id: "builtin.accuracy".to_string(),
            nullspec_id: String::new(),
            output_schema_id: "legacy/v1".to_string(),
            phys_hir_hash,
            semantic_hash: [0u8; 32],
            topic_oracle_receipt: None,
            output_schema_id_hash: hash_signal(b"evidenceos/schema_id", b"legacy/v1"),
            holdout_handle_hash: hash_signal(b"evidenceos/holdout_handle", &holdout_handle_id),
            lineage_root_hash: topic_id,
            disagreement_score: 0,
            semantic_physhir_distance_bits: 0,
            escalate_to_heavy: false,
            epoch_size: req.epoch_size,
            epoch_counter: 0,
            dlc_fuel_accumulated: 0,
            pln_config: None,
            oracle_num_symbols: req.oracle_num_symbols,
            oracle_resolution,
            state: ClaimState::Uncommitted,
            artifacts: Vec::new(),
            dependency_capsule_hashes: Vec::new(),
            dependency_items: Vec::new(),
            wasm_module: Vec::new(),
            aspec_rejection: None,
            aspec_report_summary: None,
            lane: Lane::Fast,
            heavy_lane_diversion_recorded: false,
            ledger,
            last_decision: None,
            last_capsule_hash: None,
            capsule_bytes: None,
            etl_index: None,
            oracle_pins: None,
            freeze_preimage: None,
            operation_id,
            owner_principal_id: caller.principal_id.clone(),
            created_at_unix_ms,
            trial_assignment: Some(trial_assignment),
            trial_commitment_hash: [0u8; 32],
            holdout_pool_scope: self.holdout_pool_scope,
        };

        self.state.claims.lock().insert(claim_id, claim.clone());
        {
            let mut topic_pools = self.state.topic_pools.lock();
            if let std::collections::hash_map::Entry::Vacant(entry) = topic_pools.entry(topic_id) {
                let pool =
                    TopicBudgetPool::new(hex::encode(topic_id), access_credit, access_credit)
                        .map_err(|_| Status::invalid_argument("invalid topic budget"))?;
                entry.insert(pool);
            }
        }
        {
            let holdout_scope = self.holdout_pool_scope;
            let holdout_keys =
                self.holdout_pool_keys(holdout_handle_id, &caller.principal_id, holdout_scope);
            let mut holdout_pools = self.state.holdout_pools.lock();
            for holdout_key in holdout_keys {
                holdout_pools
                    .entry(holdout_key.clone())
                    .or_insert(HoldoutBudgetPool::new(
                        holdout_key,
                        self.default_holdout_k_bits_budget,
                        self.default_holdout_access_credit_budget,
                    )?);
            }
        }
        persist_all_with_trial_router(&self.state, Some(&self.trial_router))?;
        Ok(Response::new(pb::CreateClaimResponse {
            claim_id: claim_id.to_vec(),
            state: claim.state.to_proto(),
        }))
    }

    async fn commit_artifacts(
        &self,
        request: Request<pb::CommitArtifactsRequest>,
    ) -> Result<Response<pb::CommitArtifactsResponse>, Status> {
        let caller = Self::caller_identity(request.metadata());
        let req = request.into_inner();
        if req.artifacts.is_empty() || req.artifacts.len() > MAX_ARTIFACTS {
            return Err(Status::invalid_argument(
                "artifacts count must be in [1,128]",
            ));
        }
        if req.wasm_module.is_empty() {
            return Err(Status::invalid_argument("wasm_module is required"));
        }
        let claim_id = parse_hash32(&req.claim_id, "claim_id")?;
        {
            let mut claims = self.state.claims.lock();
            let claim = claims
                .get_mut(&claim_id)
                .ok_or_else(|| Status::not_found("claim not found"))?;
            Self::enforce_claim_access(&caller, claim, "CommitArtifacts")?;
            if claim.metadata_locked
                || matches!(
                    claim.state,
                    ClaimState::Sealed
                        | ClaimState::Executing
                        | ClaimState::Settled
                        | ClaimState::Certified
                        | ClaimState::Frozen
                )
            {
                return Err(Status::failed_precondition(
                    "cannot commit artifacts after freeze",
                ));
            }
            self.transition_claim(claim, ClaimState::Committed, 0.0, 0.0, None)?;
            claim.artifacts.clear();
            claim.dependency_items.clear();
            claim.dependency_merkle_root = None;
            claim.freeze_preimage = None;
            claim.oracle_pins = None;
            let mut declared_wasm_hash = None;
            for artifact in req.artifacts {
                if artifact.kind.is_empty() || artifact.kind.len() > 64 {
                    return Err(Status::invalid_argument("artifact kind must be in [1,64]"));
                }
                let artifact_hash = parse_hash32(&artifact.artifact_hash, "artifact_hash")?;
                if artifact.kind == "wasm" {
                    declared_wasm_hash = Some(artifact_hash);
                }
                if artifact.kind == "dependency" {
                    claim.dependency_items.push(artifact_hash);
                }
                claim.artifacts.push((artifact_hash, artifact.kind));
            }

            let mut wasm_hasher = Sha256::new();
            wasm_hasher.update(&req.wasm_module);
            let wasm_hash = wasm_hasher.finalize();
            let mut wasm_hash_arr = [0u8; 32];
            wasm_hash_arr.copy_from_slice(&wasm_hash);
            match declared_wasm_hash {
                Some(declared) if declared == wasm_hash_arr => {}
                _ => {
                    return Err(Status::failed_precondition(
                        "wasm artifact hash does not match wasm_module",
                    ));
                }
            }

            let lane_cfg = LaneConfig::for_lane(
                claim.lane,
                claim.oracle_num_symbols,
                claim.ledger.access_credit_budget().unwrap_or(0.0),
            )?;
            let report = verify_aspec(&req.wasm_module, &lane_cfg.aspec_policy);
            let summary = format!(
                "lane={:?};ok={};imports={};loops={};kproxy={:.3}",
                report.lane,
                report.ok,
                report.imported_funcs,
                report.total_loops,
                report.kolmogorov_proxy_bits
            );
            claim.aspec_report_summary = Some(summary);
            if !report.ok {
                let reason = report.reasons.join("; ");
                claim.aspec_rejection = Some(reason.clone());
                self.record_incident(claim, &format!("aspec_reject:{reason}"))?;
                persist_all_with_trial_router(&self.state, Some(&self.trial_router))?;
                return Err(Status::failed_precondition("ASPEC rejected wasm module"));
            }
            claim.lane = if report.heavy_lane_flag || matches!(report.lane, AspecLane::LowAssurance)
            {
                Lane::Heavy
            } else {
                Lane::Fast
            };
            claim.heavy_lane_diversion_recorded = claim.lane == Lane::Heavy;
            claim.wasm_module = req.wasm_module;
        }
        persist_all_with_trial_router(&self.state, Some(&self.trial_router))?;
        let state = self
            .state
            .claims
            .lock()
            .get(&claim_id)
            .map(|c| c.state.to_proto())
            .ok_or_else(|| Status::internal("claim disappeared"))?;
        Ok(Response::new(pb::CommitArtifactsResponse { state }))
    }

    async fn freeze(
        &self,
        request: Request<pb::FreezeRequest>,
    ) -> Result<Response<pb::FreezeResponse>, Status> {
        let (metadata, extensions, req) = decompose_request(request);
        let response = <Self as EvidenceOsV2>::freeze_gates(
            self,
            recompose_request(
                metadata,
                extensions,
                pb::FreezeGatesRequest {
                    claim_id: req.claim_id,
                },
            ),
        )
        .await?;
        Ok(Response::new(pb::FreezeResponse {
            state: response.into_inner().state,
        }))
    }

    async fn freeze_gates(
        &self,
        request: Request<pb::FreezeGatesRequest>,
    ) -> Result<Response<pb::FreezeGatesResponse>, Status> {
        let caller = Self::caller_identity(request.metadata());
        let claim_id = parse_hash32(&request.into_inner().claim_id, "claim_id")?;
        let state = {
            let mut claims = self.state.claims.lock();
            let claim = claims
                .get_mut(&claim_id)
                .ok_or_else(|| Status::not_found("claim not found"))?;
            Self::enforce_claim_access(&caller, claim, "FreezeGates")?;
            self.freeze_claim_gates(claim).inspect_err(|_err| {
                let _ = self.record_incident(claim, "freeze_gates_failed");
            })?;
            claim.state
        };
        persist_all_with_trial_router(&self.state, Some(&self.trial_router))?;
        Ok(Response::new(pb::FreezeGatesResponse {
            state: state.to_proto(),
        }))
    }

    async fn seal(
        &self,
        request: Request<pb::SealRequest>,
    ) -> Result<Response<pb::SealResponse>, Status> {
        let (metadata, extensions, req) = decompose_request(request);
        let response = <Self as EvidenceOsV2>::seal_claim(
            self,
            recompose_request(
                metadata,
                extensions,
                pb::SealClaimRequest {
                    claim_id: req.claim_id,
                },
            ),
        )
        .await?;
        Ok(Response::new(pb::SealResponse {
            state: response.into_inner().state,
        }))
    }

    async fn seal_claim(
        &self,
        request: Request<pb::SealClaimRequest>,
    ) -> Result<Response<pb::SealClaimResponse>, Status> {
        let caller = Self::caller_identity(request.metadata());
        let claim_id = parse_hash32(&request.into_inner().claim_id, "claim_id")?;
        let state = {
            let mut claims = self.state.claims.lock();
            let claim = claims
                .get_mut(&claim_id)
                .ok_or_else(|| Status::not_found("claim not found"))?;
            Self::enforce_claim_access(&caller, claim, "SealClaim")?;
            if claim.state == ClaimState::Sealed && claim.freeze_preimage.is_some() {
                claim.state
            } else {
                self.freeze_claim_gates(claim).inspect_err(|_err| {
                    let _ = self.record_incident(claim, "seal_claim_failed");
                })?;
                claim.state
            }
        };
        persist_all_with_trial_router(&self.state, Some(&self.trial_router))?;
        Ok(Response::new(pb::SealClaimResponse {
            state: state.to_proto(),
        }))
    }

    async fn execute_claim(
        &self,
        request: Request<pb::ExecuteClaimRequest>,
    ) -> Result<Response<pb::ExecuteClaimResponse>, Status> {
        let principal_id = Self::principal_id_from_metadata(request.metadata());
        if !self.insecure_v1_enabled {
            return Err(Status::invalid_argument(
                "v1 ExecuteClaim disabled; use ExecuteClaimV2",
            ));
        }
        let caller = Self::caller_identity(request.metadata());
        let req = request.into_inner();
        let claim_id = parse_hash32(&req.claim_id, "claim_id")?;
        if req.reason_codes.len() > MAX_REASON_CODES {
            return Err(Status::invalid_argument("reason_codes length exceeds 32"));
        }
        if req.decision == pb::Decision::Unspecified as i32 {
            return Err(Status::invalid_argument("decision must not be UNSPECIFIED"));
        }

        let (capsule_hash, etl_index, state, decision, claim_id, capsule_bytes) = {
            let mut claims = self.state.claims.lock();
            let claim = claims
                .get_mut(&claim_id)
                .ok_or_else(|| Status::not_found("claim not found"))?;
            let claim_id_hex = hex::encode(claim.claim_id);
            let span = tracing::info_span!("execute_claim", operation_id=%claim.operation_id, claim_id=%claim_id_hex);
            let _guard = span.enter();
            if claim.state == ClaimState::Settled || claim.state == ClaimState::Certified {
                return Err(Status::failed_precondition("execution already settled"));
            }
            Self::enforce_claim_access(&caller, claim, "ExecuteClaim")?;
            claim.operation_id = build_operation_id(
                claim.topic_id,
                claim.dependency_merkle_root,
                claim.claim_id,
                "execute_claim_v1",
                Some(claim.phys_hir_hash),
            );
            self.transition_claim(claim, ClaimState::Executing, 0.0, 0.0, None)?;

            let vault = VaultEngine::new().map_err(map_vault_error)?;
            let context = vault_context(
                claim,
                default_registry_nullspec()?,
                self.holdout_provider.as_ref(),
            )?;
            let vault_result =
                match vault.execute(&claim.wasm_module, &context, vault_config(claim)?) {
                    Ok(v) => v,
                    Err(err) => {
                        self.record_incident(claim, "execution_failure")?;
                        return Err(map_vault_error(err));
                    }
                };
            let emitted_output = vault_result.canonical_output;
            let fuel_used = vault_result.fuel_used;
            let epoch_budget = claim.epoch_size;
            let fuel_total = padded_fuel_total(epoch_budget, fuel_used, claim.pln_config.as_ref())?;
            let padding_fuel = fuel_total.saturating_sub(fuel_used);
            burn_padding_fuel(&vault, &context, padding_fuel)?;
            claim.dlc_fuel_accumulated = claim.dlc_fuel_accumulated.saturating_add(fuel_total);
            claim.epoch_counter = current_logical_epoch(claim)?;
            let trace_hash = vault_result.judge_trace_hash;
            if !req.canonical_output.is_empty() && req.canonical_output != emitted_output {
                self.record_incident(claim, "canonical_output_mismatch")?;
                return Err(Status::invalid_argument(
                    "canonical_output mismatch with wasm emission",
                ));
            }
            let canonical_output = emitted_output;
            let _ = claim
                .oracle_resolution
                .validate_canonical_bytes(&canonical_output)
                .map_err(|_| {
                    let _ = self.record_incident(claim, "non_canonical_output");
                    Status::invalid_argument("non-canonical output")
                })?;

            let charge_bits = claim.oracle_resolution.bits_per_call()
                * f64::from(vault_result.oracle_calls.max(1));
            let dependence_multiplier = self.dependence_tax_multiplier;
            let taxed_bits = charge_bits * dependence_multiplier;
            let covariance_charge = taxed_bits - charge_bits;
            claim
                .ledger
                .charge_all(
                    taxed_bits,
                    0.0,
                    0.0,
                    taxed_bits,
                    "structured_output",
                    json!({
                        "post_canonical_bits": charge_bits,
                        "dependence_multiplier": dependence_multiplier,
                        "taxed_k_bits": taxed_bits,
                    }),
                )
                .map_err(|_| {
                    let _ = self.record_incident(claim, "ledger_overrun");
                    Status::failed_precondition("ledger budget exhausted")
                })?;
            {
                let mut topic_pools = self.state.topic_pools.lock();
                let pool = topic_pools
                    .get_mut(&claim.topic_id)
                    .ok_or_else(|| Status::failed_precondition("missing topic budget pool"))?;
                if pool
                    .charge(taxed_bits, taxed_bits, covariance_charge)
                    .is_err()
                {
                    let _ = self.record_incident(claim, "topic_budget_exhausted");
                    return Err(Status::failed_precondition("topic budget exhausted"));
                }
            }
            {
                let mut holdout_pools = self.state.holdout_pools.lock();
                let holdout_keys = self.holdout_pool_keys(
                    claim.holdout_handle_id,
                    &claim.owner_principal_id,
                    claim.holdout_pool_scope,
                );
                for holdout_key in holdout_keys {
                    let pool = holdout_pools.get_mut(&holdout_key).ok_or_else(|| {
                        Status::failed_precondition("missing holdout budget pool")
                    })?;
                    if pool.charge(taxed_bits, taxed_bits).is_err() {
                        let _ = self.record_incident(claim, "holdout_budget_exhausted");
                        return Err(Status::failed_precondition("holdout budget exhausted"));
                    }
                }
            }
            claim
                .ledger
                .charge_kout_bits(vault_result.kout_bits_total)
                .map_err(|_| {
                    let _ = self.record_incident(claim, "ledger_kout_overrun");
                    Status::failed_precondition("ledger kout budget exhausted")
                })?;
            let principal_k_bits =
                if taxed_bits.is_finite() && vault_result.kout_bits_total.is_finite() {
                    Some((taxed_bits + vault_result.kout_bits_total).max(0.0).ceil() as u64)
                } else {
                    None
                };
            let principal_fuel = if fuel_total > 0 {
                Some(fuel_total)
            } else {
                None
            };
            let principal_mem_pages = if vault_result.max_memory_pages > 0 {
                Some(vault_result.max_memory_pages)
            } else {
                None
            };
            self.charge_principal_credit(
                &principal_id,
                principal_k_bits,
                principal_fuel,
                principal_mem_pages,
            )?;
            if claim.lane == Lane::Heavy && canonical_output.len() > 1 {
                self.record_incident(claim, "heavy_lane_output_policy")?;
                return Err(Status::failed_precondition(
                    "heavy lane output policy rejected",
                ));
            }
            let e_value = if req.decision == pb::Decision::Approve as i32 {
                2.0
            } else {
                1.25
            };
            claim
                .ledger
                .settle_e_value(e_value, "decision", json!({"decision": req.decision}))
                .map_err(|_| Status::invalid_argument("invalid e-value"))?;

            self.transition_claim(
                claim,
                ClaimState::Settled,
                taxed_bits + vault_result.kout_bits_total,
                e_value,
                None,
            )?;
            if claim.lane == Lane::Heavy {
                self.transition_claim(claim, ClaimState::Frozen, 0.0, 0.0, None)?;
            } else if claim.ledger.can_certify() {
                self.transition_claim(claim, ClaimState::Certified, 0.0, 0.0, None)?;
            } else {
                self.transition_claim(claim, ClaimState::Revoked, 0.0, 0.0, None)?;
            }

            let mut capsule = ClaimCapsule::new(
                hex::encode(claim.claim_id),
                hex::encode(claim.topic_id),
                claim.output_schema_id.clone(),
                claim
                    .artifacts
                    .iter()
                    .map(|(hash, kind)| ManifestEntry {
                        kind: kind.clone(),
                        hash_hex: hex::encode(hash),
                    })
                    .collect(),
                claim.dependency_capsule_hashes.clone(),
                &canonical_output,
                &claim.wasm_module,
                &claim.holdout_handle_id,
                &claim.ledger,
                e_value,
                claim.state == ClaimState::Certified,
                req.decision,
                req.reason_codes.clone(),
                Vec::new(),
                &trace_hash,
                claim.holdout_ref.clone(),
                format!("deterministic-kernel-{}", env!("CARGO_PKG_VERSION")),
                "aspec.v1".to_string(),
                "evidenceos.v1".to_string(),
                fuel_total as f64,
            );
            self.populate_tee_attestation(&mut capsule, &claim.wasm_module)?;
            capsule.semantic_hash_hex = Some(hex::encode(claim.semantic_hash));
            capsule.physhir_hash_hex = Some(hex::encode(claim.phys_hir_hash));
            capsule.lineage_root_hash_hex = Some(hex::encode(claim.lineage_root_hash));
            capsule.output_schema_id_hash_hex = Some(hex::encode(claim.output_schema_id_hash));
            capsule.holdout_handle_hash_hex = Some(hex::encode(claim.holdout_handle_hash));
            capsule.disagreement_score = Some(claim.disagreement_score);
            capsule.semantic_physhir_distance_bits = Some(claim.semantic_physhir_distance_bits);
            capsule.escalate_to_heavy = Some(claim.escalate_to_heavy);
            capsule.topic_oracle_receipt =
                claim
                    .topic_oracle_receipt
                    .as_ref()
                    .map(|receipt| TopicOracleReceiptLike {
                        claim_manifest_hash_hex: hex::encode(receipt.claim_manifest_hash),
                        semantic_hash_hex: hex::encode(receipt.semantic_hash),
                        model_id: receipt.model_id.clone(),
                        timestamp_unix: receipt.timestamp_unix,
                        signature_hex: hex::encode(&receipt.signature),
                    });
            capsule.trial_commitment_hash_hex = Some(hex::encode(claim.trial_commitment_hash));
            if let Some(assignment) = claim.trial_assignment.as_ref() {
                capsule.trial_commitment_schema_version =
                    Some(u32::from(TRIAL_COMMITMENT_SCHEMA_VERSION));
                capsule.trial_arm_id = Some(u32::from(assignment.arm_id));
                capsule.trial_intervention_id = Some(assignment.intervention_id.clone());
                capsule.trial_intervention_version = Some(assignment.intervention_version.clone());
                capsule.trial_arm_parameters_hash_hex =
                    Some(hex::encode(assignment.arm_parameters_hash));
                capsule.trial_nonce_hex = Some(hex::encode(assignment.trial_nonce));
                let trial_config_hash_hex = self.trial_config_hash.map(hex::encode);
                capsule.trial_config_hash_hex = trial_config_hash_hex.clone();
                capsule.trial = Some(TrialMetadata {
                    intervention_id: Some(assignment.intervention_id.clone()),
                    intervention_version: Some(assignment.intervention_version.clone()),
                    arm_parameters_hash_hex: Some(hex::encode(assignment.arm_parameters_hash)),
                    arm_id: Some(u32::from(assignment.arm_id)),
                    trial_nonce_hex: Some(hex::encode(assignment.trial_nonce)),
                    trial_config_hash_hex,
                    allocator_snapshot_hash_hex: assignment
                        .allocator_snapshot_hash
                        .map(hex::encode),
                });
            }
            capsule.state = if claim.state == ClaimState::Certified {
                CoreClaimState::Certified
            } else {
                CoreClaimState::Settled
            };
            let capsule_bytes = capsule
                .to_json_bytes()
                .map_err(|_| Status::internal("capsule serialization failed"))?;
            let capsule_hash = decode_hex_hash32(
                &capsule
                    .capsule_hash_hex()
                    .map_err(|_| Status::internal("capsule hashing failed"))?,
                "capsule_hash",
            )?;
            if claim.lineage_root_hash == [0u8; 32] {
                claim.lineage_root_hash = capsule_hash;
            }
            if claim.lineage_root_hash == [0u8; 32] {
                claim.lineage_root_hash = capsule_hash;
            }
            let etl_index = {
                let mut etl = self.state.etl.lock();
                let (idx, _) = etl
                    .append(&capsule_bytes)
                    .map_err(|_| Status::internal("etl append failed"))?;
                etl.sync_data()
                    .map_err(|_| Status::internal("etl sync failed"))?;
                let root = etl.root_hash();
                let inc = etl
                    .inclusion_proof(idx)
                    .map_err(|_| Status::internal("inclusion proof failed"))?;
                if !verify_inclusion_proof(
                    &inc,
                    &etl.leaf_hash_at(idx)
                        .map_err(|_| Status::internal("leaf missing"))?,
                    idx as usize,
                    etl.tree_size() as usize,
                    &root,
                ) {
                    self.record_incident(claim, "etl_inclusion_verify_failed")?;
                    return Err(Status::internal("etl proof verification failed"));
                }
                let old_size = idx + 1;
                let new_size = etl.tree_size();
                let cons = etl
                    .consistency_proof(old_size, new_size)
                    .map_err(|_| Status::internal("consistency proof failed"))?;
                let old_root = etl
                    .root_at_size(old_size)
                    .map_err(|_| Status::internal("old root missing"))?;
                if !verify_consistency_proof(
                    &old_root,
                    &root,
                    old_size as usize,
                    new_size as usize,
                    &cons,
                ) {
                    self.record_incident(claim, "etl_consistency_verify_failed")?;
                    return Err(Status::internal("etl consistency verification failed"));
                }
                idx
            };
            claim.last_decision = Some(req.decision);
            claim.last_capsule_hash = Some(capsule_hash);
            claim.capsule_bytes = Some(capsule_bytes.clone());
            claim.etl_index = Some(etl_index);
            (
                capsule_hash,
                etl_index,
                claim.state,
                req.decision,
                claim.claim_id,
                capsule_bytes,
            )
        };

        let pending = PendingMutation::Execute {
            claim_id,
            state,
            decision,
            capsule_hash,
            capsule_bytes,
            etl_index: Some(etl_index),
        };
        persist_pending_mutation(&self.state, &pending)?;
        maybe_abort_failpoint("after_etl_append_execute_claim");
        persist_all_with_trial_router(&self.state, Some(&self.trial_router))?;
        clear_pending_mutation(&self.state, claim_id)?;

        Ok(Response::new(pb::ExecuteClaimResponse {
            state: state.to_proto(),
            capsule_hash: capsule_hash.to_vec(),
            etl_index,
        }))
    }

    async fn create_claim_v2(
        &self,
        request: Request<pb::CreateClaimV2Request>,
    ) -> Result<Response<pb::CreateClaimV2Response>, Status> {
        let caller = Self::caller_identity(request.metadata());
        let principal_id = caller.principal_id.clone();
        let request_id = Self::request_id_from_metadata(request.metadata())?;
        let req_msg = request.get_ref().clone();
        let idempotency = self
            .idempotency_lookup::<pb::CreateClaimV2Request, pb::CreateClaimV2Response>(
                "/evidenceos.v2.EvidenceOS/CreateClaimV2",
                &principal_id,
                &request_id,
                &req_msg,
            )?;
        let idempotency_context = match idempotency {
            IdempotencyLookup::Cached(cached) => return Ok(Response::new(cached)),
            IdempotencyLookup::Miss(ctx) => ctx,
        };
        let req = request.into_inner();
        validate_required_str_field(&req.claim_name, "claim_name", 128)?;
        let oracle_id = if req.oracle_id.trim().is_empty() {
            "builtin.accuracy".to_string()
        } else {
            req.oracle_id.trim().to_string()
        };
        validate_required_str_field(&oracle_id, "oracle_id", 128)?;
        {
            let operator_config = self.state.operator_config.lock();
            if !operator_config.oracle_ttl_epochs.is_empty()
                && !operator_config.oracle_ttl_epochs.contains_key(&oracle_id)
            {
                return Err(Status::invalid_argument("unknown oracle_id"));
            }
        }
        let nullspec_id = req.nullspec_id.trim().to_string();
        if !nullspec_id.is_empty() {
            validate_required_str_field(&nullspec_id, "nullspec_id", 128)?;
        }
        if req.epoch_size == 0 {
            return Err(Status::invalid_argument("epoch_size must be > 0"));
        }
        if let Some(dp_epsilon_budget) = req.dp_epsilon_budget {
            Self::validate_budget_value(dp_epsilon_budget, "dp_epsilon_budget")?;
        }
        if let Some(dp_delta_budget) = req.dp_delta_budget {
            Self::validate_budget_value(dp_delta_budget, "dp_delta_budget")?;
        }
        let holdout_descriptor = self.holdout_provider.resolve(&req.holdout_ref)?;
        let metadata = req
            .metadata
            .ok_or_else(|| Status::invalid_argument("metadata is required"))?;
        let epoch_config_ref = metadata.epoch_config_ref.clone();
        validate_required_str_field(
            &epoch_config_ref,
            "metadata.epoch_config_ref",
            MAX_METADATA_FIELD_LEN,
        )?;
        let (dlc_cfg, pln_cfg) =
            load_epoch_runtime_config(&self.state.data_path, &epoch_config_ref, req.epoch_size)?;
        validate_required_str_field(
            &metadata.output_schema_id,
            "metadata.output_schema_id",
            MAX_METADATA_FIELD_LEN,
        )?;
        let canonical_output_schema_id =
            structured_claims::canonicalize_schema_id(&metadata.output_schema_id)
                .map_err(|_| {
                    Status::invalid_argument(
                "unsupported metadata.output_schema_id; canonicalize to cbrn-sc.v1 or legacy/v1",
            )
                })?
                .to_string();
        let signals_hint = req.signals.as_ref();
        if let Some(signals) = signals_hint {
            if !signals.phys_hir_signature_hash.is_empty()
                && signals.phys_hir_signature_hash.len() != 32
            {
                return Err(Status::invalid_argument(
                    "signals.phys_hir_signature_hash must be 0 or 32 bytes",
                ));
            }
            if !signals.semantic_hash.is_empty() && signals.semantic_hash.len() != 32 {
                return Err(Status::invalid_argument(
                    "signals.semantic_hash must be 0 or 32 bytes",
                ));
            }
            if !signals.dependency_merkle_root.is_empty()
                && signals.dependency_merkle_root.len() != 32
            {
                return Err(Status::invalid_argument(
                    "signals.dependency_merkle_root must be 0 or 32 bytes",
                ));
            }
        }
        let dependency_merkle_root = signals_hint.and_then(|signals| {
            if signals.dependency_merkle_root.len() == 32 {
                let mut b = [0u8; 32];
                b.copy_from_slice(&signals.dependency_merkle_root);
                Some(b)
            } else {
                None
            }
        });
        let holdout_handle_id = holdout_descriptor.handle;
        let topic_manifest = TopicManifestForHash {
            claim_name: req.claim_name.clone(),
            epoch_config_ref: epoch_config_ref.clone(),
            output_schema_id: canonical_output_schema_id.clone(),
            holdout_ref: req.holdout_ref.clone(),
            holdout_handle_hex: hex::encode(holdout_handle_id),
            nullspec_id_hex: None,
            wasm_code_hash_hex: hex::encode([0u8; 32]),
            oracle_num_symbols: req.oracle_num_symbols,
            epoch_size: dlc_cfg.epoch_size,
        };
        let claim_manifest_hash = compute_topic_manifest_hash(&topic_manifest)?;
        let semantic_hash = derive_server_topic_semantic_hash(claim_manifest_hash);
        let phys =
            derive_server_topic_physhir_hash(claim_manifest_hash, &canonical_output_schema_id);
        let topic_oracle_receipt = build_topic_oracle_receipt(
            self.active_signing_key()?,
            claim_manifest_hash,
            semantic_hash,
            "deterministic.manifest.v1",
        );
        let output_schema_id_hash = hash_signal(
            b"evidenceos/schema_id",
            canonical_output_schema_id.as_bytes(),
        );
        let holdout_handle_hash = hash_signal(b"evidenceos/holdout_handle", &holdout_handle_id);
        let lineage_root_hash = dependency_merkle_root.unwrap_or([0u8; 32]);

        let topic = compute_topic_id(
            &CoreClaimMetadataV2 {
                lane: metadata.lane.clone(),
                alpha_micros: metadata.alpha_micros,
                epoch_config_ref: epoch_config_ref.clone(),
                output_schema_id: canonical_output_schema_id.clone(),
            },
            &TopicSignals {
                semantic_hash,
                physhir_hash: phys,
                lineage_root_hash,
                output_schema_id_hash,
                holdout_handle_hash,
            },
        );

        let alpha = (metadata.alpha_micros as f64) / 1_000_000.0;
        let access_credit = req.access_credit as f64;
        Self::validate_budget_value(access_credit, "access_credit")?;
        self.admission_provider
            .admit(&caller.principal_id, req.access_credit)?;
        let requested = requested_lane(&metadata.lane)?;
        let lane = if topic.escalate_to_heavy {
            Lane::Heavy
        } else {
            requested
        };
        if lane != requested {
            self.telemetry
                .record_lane_escalation(Self::lane_name(requested), Self::lane_name(lane));
        }
        let domain = self.domain_for_policy(&req.claim_name, &req.holdout_ref, &nullspec_id)?;
        let lane = match self
            .domain_safety
            .decision_for(&domain, &canonical_output_schema_id, lane)
        {
            DomainSafetyDecision::Allow => lane,
            DomainSafetyDecision::ForceHeavyLane => {
                self.telemetry
                    .record_lane_escalation(Self::lane_name(lane), Self::lane_name(Lane::Heavy));
                Lane::Heavy
            }
            DomainSafetyDecision::Reject => {
                return Err(Status::failed_precondition(
                    "domain policy requires CBRN_SC_V1 structured outputs",
                ));
            }
        };
        let lane_cfg = LaneConfig::for_lane(lane, req.oracle_num_symbols, access_credit)?;
        let claim_pln_cfg = claim_pln_config(lane, &pln_cfg)?;
        let oracle_resolution = lane_cfg.oracle_resolution.clone();

        let mut id_payload = Vec::new();
        id_payload.extend_from_slice(&topic.topic_id);
        id_payload.extend_from_slice(&holdout_handle_id);
        id_payload.extend_from_slice(&phys);
        id_payload.extend_from_slice(&dlc_cfg.epoch_size.to_be_bytes());
        id_payload.extend_from_slice(&oracle_resolution.num_symbols.to_be_bytes());
        let claim_id = sha256_domain(DOMAIN_CLAIM_ID, &id_payload);

        if let Some(existing) = self.state.claims.lock().get(&claim_id).cloned() {
            return Ok(Response::new(pb::CreateClaimV2Response {
                claim_id: claim_id.to_vec(),
                topic_id: existing.topic_id.to_vec(),
                state: existing.state.to_proto(),
            }));
        }

        let trial_nonce = generate_trial_nonce()?;
        let trial_assignment = self.trial_router.assign(
            trial_nonce,
            &StratumKey::from_baseline(BaselineCovariates {
                lane: Self::lane_name(lane).to_string(),
                holdout_ref: req.holdout_ref.clone(),
                oracle_id: oracle_id.clone(),
                nullspec_id: nullspec_id.clone(),
            }),
        )?;
        let intervention_delta =
            validate_and_build_delta(&self.trial_router.intervention_actions(&trial_assignment)?)?;
        let adjusted_alpha = (alpha * f64::from(intervention_delta.alpha_scale_ppm)) / 1_000_000.0;
        let adjusted_access_credit =
            (access_credit * f64::from(intervention_delta.access_credit_scale_ppm)) / 1_000_000.0;
        Self::validate_budget_value(adjusted_access_credit, "adjusted_access_credit")?;

        let mut lane_cfg = lane_cfg;
        lane_cfg.access_credit_budget = adjusted_access_credit;
        lane_cfg.k_bits_budget =
            (lane_cfg.k_bits_budget * f64::from(intervention_delta.k_bits_scale_ppm)) / 1_000_000.0;
        Self::validate_budget_value(lane_cfg.k_bits_budget, "adjusted_k_bits_budget")?;
        let ledger = ConservationLedger::new(adjusted_alpha)
            .map_err(|_| Status::invalid_argument("alpha_micros must encode alpha in (0,1)"))
            .map(|l| {
                l.with_budgets(
                    Some(lane_cfg.k_bits_budget),
                    Some(lane_cfg.access_credit_budget),
                )
                .with_dp_budgets(req.dp_epsilon_budget, req.dp_delta_budget)
            })?;

        let operation_id = build_operation_id(
            topic.topic_id,
            dependency_merkle_root,
            claim_id,
            "create_claim_v2",
            Some(phys),
        );
        self.observe_probe(
            caller.principal_id.clone(),
            operation_id.clone(),
            hex::encode(topic.topic_id),
            hex::encode(semantic_hash),
        )?;
        let created_at_unix_ms = current_time_unix_ms()?;
        let claim = Claim {
            claim_id,
            topic_id: topic.topic_id,
            dependency_merkle_root,
            holdout_handle_id,
            holdout_ref: req.holdout_ref,
            epoch_config_ref,
            holdout_len: holdout_descriptor.len as u64,
            metadata_locked: false,
            claim_name: req.claim_name,
            oracle_id,
            nullspec_id,
            output_schema_id: canonical_output_schema_id,
            phys_hir_hash: phys,
            semantic_hash,
            topic_oracle_receipt: Some(topic_oracle_receipt),
            output_schema_id_hash,
            holdout_handle_hash,
            lineage_root_hash,
            disagreement_score: topic.disagreement_score,
            semantic_physhir_distance_bits: topic.semantic_physhir_distance_bits,
            escalate_to_heavy: topic.escalate_to_heavy,
            epoch_size: dlc_cfg.epoch_size,
            epoch_counter: 0,
            dlc_fuel_accumulated: 0,
            pln_config: Some(claim_pln_cfg),
            oracle_num_symbols: req.oracle_num_symbols,
            oracle_resolution,
            state: ClaimState::Uncommitted,
            artifacts: Vec::new(),
            dependency_capsule_hashes: Vec::new(),
            dependency_items: Vec::new(),
            wasm_module: Vec::new(),
            aspec_rejection: None,
            aspec_report_summary: None,
            lane,
            heavy_lane_diversion_recorded: lane == Lane::Heavy,
            ledger,
            last_decision: None,
            last_capsule_hash: None,
            capsule_bytes: None,
            etl_index: None,
            oracle_pins: None,
            freeze_preimage: None,
            operation_id,
            owner_principal_id: caller.principal_id.clone(),
            created_at_unix_ms,
            trial_assignment: Some(trial_assignment),
            trial_commitment_hash: [0u8; 32],
            holdout_pool_scope: self.holdout_scope_for(&holdout_descriptor),
        };
        {
            let mut claims = self.state.claims.lock();
            if let Some(existing) = claims.get(&claim_id).cloned() {
                let response = pb::CreateClaimV2Response {
                    claim_id: claim_id.to_vec(),
                    topic_id: existing.topic_id.to_vec(),
                    state: existing.state.to_proto(),
                };
                self.idempotency_store_success(idempotency_context.clone(), &response)?;
                return Ok(Response::new(response));
            }
            claims.insert(claim_id, claim.clone());
        }
        self.state
            .topic_pools
            .lock()
            .entry(topic.topic_id)
            .or_insert(
                TopicBudgetPool::new(
                    hex::encode(topic.topic_id),
                    lane_cfg.k_bits_budget,
                    lane_cfg.access_credit_budget,
                )
                .map_err(|_| Status::invalid_argument("invalid topic budget"))?,
            );
        {
            let holdout_scope = self.holdout_pool_scope;
            let holdout_keys =
                self.holdout_pool_keys(holdout_handle_id, &caller.principal_id, holdout_scope);
            let mut holdout_pools = self.state.holdout_pools.lock();
            for holdout_key in holdout_keys {
                holdout_pools
                    .entry(holdout_key.clone())
                    .or_insert(HoldoutBudgetPool::new(
                        holdout_key,
                        self.default_holdout_k_bits_budget,
                        self.default_holdout_access_credit_budget,
                    )?);
            }
        }
        persist_all_with_trial_router(&self.state, Some(&self.trial_router))?;
        let response = pb::CreateClaimV2Response {
            claim_id: claim_id.to_vec(),
            topic_id: claim.topic_id.to_vec(),
            state: claim.state.to_proto(),
        };
        self.idempotency_store_success(idempotency_context, &response)?;
        Ok(Response::new(response))
    }

    async fn execute_claim_v2(
        &self,
        request: Request<pb::ExecuteClaimV2Request>,
    ) -> Result<Response<pb::ExecuteClaimV2Response>, Status> {
        let caller = Self::caller_identity(request.metadata());
        let principal_id = caller.principal_id.clone();
        let request_id = Self::request_id_from_metadata(request.metadata())?;
        let req_msg = request.get_ref().clone();
        let idempotency = self
            .idempotency_lookup::<pb::ExecuteClaimV2Request, pb::ExecuteClaimV2Response>(
                "/evidenceos.v2.EvidenceOS/ExecuteClaimV2",
                &principal_id,
                &request_id,
                &req_msg,
            )?;
        let idempotency_context = match idempotency {
            IdempotencyLookup::Cached(cached) => return Ok(Response::new(cached)),
            IdempotencyLookup::Miss(ctx) => ctx,
        };
        let req = request.into_inner();
        let claim_id = parse_hash32(&req.claim_id, "claim_id")?;
        let (
            state,
            decision,
            reason_codes,
            canonical_output,
            e_value,
            certified,
            capsule_hash,
            etl_index,
            claim_id,
            capsule_bytes,
            stored_etl_index,
        ) = {
            let mut claims = self.state.claims.lock();
            let claim = claims
                .get_mut(&claim_id)
                .ok_or_else(|| Status::not_found("claim not found"))?;
            let claim_id_hex = hex::encode(claim.claim_id);
            let span = tracing::info_span!("execute_claim_v2", operation_id=%claim.operation_id, claim_id=%claim_id_hex);
            let _guard = span.enter();
            let current_epoch = self.current_epoch_for_claim(claim)?;
            Self::maybe_mark_stale(claim, current_epoch)?;
            if claim.state == ClaimState::Stale {
                return Err(Status::failed_precondition(
                    "claim is stale; re-freeze before execution",
                ));
            }
            if claim.state != ClaimState::Sealed {
                return Err(Status::failed_precondition(
                    "claim must be SEALED before execution",
                ));
            }
            if claim.freeze_preimage.is_none() {
                return Err(Status::failed_precondition("freeze gates not completed"));
            }
            let pins = claim
                .oracle_pins
                .as_ref()
                .ok_or_else(|| Status::failed_precondition("oracle pins missing"))?;
            let current_resolution_hash = oracle_resolution_hash(&claim.oracle_resolution)?;
            if pins.oracle_resolution_hash != current_resolution_hash {
                self.record_incident(claim, "oracle_resolution_pins_mismatch")?;
                return Err(Status::failed_precondition(
                    "oracle resolution hash mismatch with sealed pins",
                ));
            }
            claim.operation_id = build_operation_id(
                claim.topic_id,
                claim.dependency_merkle_root,
                claim.claim_id,
                "execute_claim_v2",
                Some(claim.phys_hir_hash),
            );
            Self::enforce_claim_access(&caller, claim, "ExecuteClaimV2")?;
            self.observe_probe(
                caller.principal_id.clone(),
                claim.operation_id.clone(),
                hex::encode(claim.topic_id),
                hex::encode(claim.phys_hir_hash),
            )?;
            let nullspec_store = NullSpecStore::open(&self.state.data_path)
                .map_err(|_| Status::internal("nullspec store init failed"))?;
            let active_id = if claim.nullspec_id.is_empty() {
                match nullspec_store
                    .active_for(&claim.claim_name, &claim.holdout_ref)
                    .map_err(|_| Status::internal("nullspec mapping read failed"))?
                {
                    Some(id) => id,
                    None => {
                        self.record_incident(claim, "nullspec_missing")?;
                        return Err(Status::failed_precondition("missing active nullspec"));
                    }
                }
            } else {
                let decoded = hex::decode(&claim.nullspec_id)
                    .map_err(|_| Status::invalid_argument("invalid nullspec_id hex"))?;
                decoded
                    .as_slice()
                    .try_into()
                    .map_err(|_| Status::invalid_argument("invalid nullspec_id length"))?
            };
            let contract = nullspec_store
                .get(&active_id)
                .map_err(|_| Status::failed_precondition("active nullspec not found"))?;
            if contract.is_expired(current_epoch) {
                self.record_incident(claim, "nullspec_expired")?;
                return Err(Status::failed_precondition("active nullspec expired"));
            }
            let expected_resolution_hash = oracle_resolution_hash(&claim.oracle_resolution)?;
            if contract.oracle_resolution_hash != expected_resolution_hash {
                self.record_incident(claim, "nullspec_resolution_hash_mismatch")?;
                return Err(Status::failed_precondition(
                    "nullspec resolution hash mismatch",
                ));
            }
            if let Some(contract_calibration_hash) = contract.calibration_manifest_hash {
                if contract_calibration_hash != claim.oracle_resolution.calibration_manifest_hash {
                    self.record_incident(claim, "nullspec_calibration_hash_mismatch")?;
                    return Err(Status::failed_precondition(
                        "nullspec calibration hash mismatch",
                    ));
                }
            }

            let oracle_ttl_expired = claim.oracle_resolution.ttl_expired(current_epoch);
            let oracle_ttl_escalated = if oracle_ttl_expired {
                match self.oracle_ttl_policy {
                    OracleTtlPolicy::RejectExpired => {
                        self.record_incident(claim, "oracle_expired")?;
                        return Err(Status::failed_precondition("OracleExpired"));
                    }
                    OracleTtlPolicy::EscalateToHeavy => {
                        if claim.lane != Lane::Heavy {
                            self.record_incident(claim, "oracle_expired")?;
                            return Err(Status::failed_precondition("OracleExpired"));
                        }
                        self.record_incident(claim, "oracle_expired_escalated_to_heavy")?;
                        true
                    }
                }
            } else {
                false
            };

            self.transition_claim(claim, ClaimState::Executing, 0.0, 0.0, None)?;
            let vault = VaultEngine::new().map_err(map_vault_error)?;
            let registry = self.ensure_nullspec_registry_fresh()?;
            let reg_nullspec = registry
                .get(&hex::encode(contract.nullspec_id))
                .cloned()
                .ok_or_else(|| Status::failed_precondition("active nullspec id not in registry"))?;
            let context = vault_context(claim, reg_nullspec, self.holdout_provider.as_ref())?;
            let vault_result =
                match vault.execute(&claim.wasm_module, &context, vault_config(claim)?) {
                    Ok(v) => v,
                    Err(err) => {
                        self.record_incident(claim, "execution_failure")?;
                        return Err(map_vault_error(err));
                    }
                };
            self.telemetry.record_oracle_calls(
                Self::lane_name(claim.lane),
                "vault_oracle_bucket",
                u64::from(vault_result.oracle_calls),
            );
            let canonical_output = vault_result.canonical_output.clone();
            let fuel_used = vault_result.fuel_used;
            let epoch_budget = claim.epoch_size;
            let fuel_total = padded_fuel_total(epoch_budget, fuel_used, claim.pln_config.as_ref())?;
            let padding_fuel = fuel_total.saturating_sub(fuel_used);
            burn_padding_fuel(&vault, &context, padding_fuel)?;
            claim.dlc_fuel_accumulated = claim.dlc_fuel_accumulated.saturating_add(fuel_total);
            claim.epoch_counter = current_logical_epoch(claim)?;
            let trace_hash = vault_result.judge_trace_hash;
            if claim.output_schema_id == structured_claims::LEGACY_SCHEMA_ID {
                let _sym = decode_canonical_symbol(&canonical_output, claim.oracle_num_symbols)?;
            }
            let mut physhir_mismatch = false;
            let mut magnitude_envelope_violation = false;
            if claim.output_schema_id != structured_claims::LEGACY_SCHEMA_ID {
                if let Ok(validated) = structured_claims::validate_and_canonicalize(
                    &claim.output_schema_id,
                    &canonical_output,
                ) {
                    magnitude_envelope_violation = validated.envelope_violation.is_some();
                    let computed_phys =
                        evidenceos_core::physhir::physhir_signature_hash(&validated.claim);
                    let topic_check = compute_topic_id(
                        &CoreClaimMetadataV2 {
                            lane: Self::lane_name(claim.lane).to_string(),
                            alpha_micros: (claim.ledger.alpha() * 1_000_000.0).round() as u32,
                            epoch_config_ref: "execute".to_string(),
                            output_schema_id: claim.output_schema_id.clone(),
                        },
                        &TopicSignals {
                            semantic_hash: claim.semantic_hash,
                            physhir_hash: computed_phys,
                            lineage_root_hash: claim.lineage_root_hash,
                            output_schema_id_hash: claim.output_schema_id_hash,
                            holdout_handle_hash: claim.holdout_handle_hash,
                        },
                    );
                    claim.phys_hir_hash = computed_phys;
                    claim.disagreement_score = topic_check.disagreement_score;
                    claim.semantic_physhir_distance_bits =
                        topic_check.semantic_physhir_distance_bits;
                    claim.escalate_to_heavy = topic_check.escalate_to_heavy;
                    physhir_mismatch = topic_check.escalate_to_heavy;
                }
            }
            let charge_bits = claim.oracle_resolution.bits_per_call()
                * f64::from(vault_result.oracle_calls.max(1));
            let dependence_multiplier = if oracle_ttl_escalated {
                self.dependence_tax_multiplier * self.oracle_ttl_escalation_tax_multiplier
            } else {
                self.dependence_tax_multiplier
            };
            let taxed_bits = charge_bits * dependence_multiplier;
            let covariance_charge = taxed_bits - charge_bits;
            claim
                .ledger
                .charge_all(
                    taxed_bits,
                    0.0,
                    0.0,
                    taxed_bits,
                    "structured_output",
                    json!({
                        "post_canonical_bits": charge_bits,
                        "dependence_multiplier": dependence_multiplier,
                        "taxed_k_bits": taxed_bits,
                    }),
                )
                .map_err(|_| Status::failed_precondition("ledger budget exhausted"))?;
            claim
                .ledger
                .charge_kout_bits(vault_result.kout_bits_total)
                .map_err(|_| Status::failed_precondition("ledger kout budget exhausted"))?;
            {
                let mut topic_pools = self.state.topic_pools.lock();
                let pool = topic_pools
                    .get_mut(&claim.topic_id)
                    .ok_or_else(|| Status::failed_precondition("missing topic budget pool"))?;
                if pool
                    .charge(
                        taxed_bits + vault_result.kout_bits_total,
                        taxed_bits + vault_result.kout_bits_total,
                        covariance_charge,
                    )
                    .is_err()
                {
                    let _ = self.record_incident(claim, "topic_budget_exhausted");
                    return Err(Status::failed_precondition("topic budget exhausted"));
                }
            }
            {
                let mut holdout_pools = self.state.holdout_pools.lock();
                let holdout_keys = self.holdout_pool_keys(
                    claim.holdout_handle_id,
                    &claim.owner_principal_id,
                    claim.holdout_pool_scope,
                );
                for holdout_key in holdout_keys {
                    let pool = holdout_pools.get_mut(&holdout_key).ok_or_else(|| {
                        Status::failed_precondition("missing holdout budget pool")
                    })?;
                    if pool
                        .charge(
                            taxed_bits + vault_result.kout_bits_total,
                            taxed_bits + vault_result.kout_bits_total,
                        )
                        .is_err()
                    {
                        let _ = self.record_incident(claim, "holdout_budget_exhausted");
                        return Err(Status::failed_precondition("holdout budget exhausted"));
                    }
                }
            }
            let principal_k_bits =
                if taxed_bits.is_finite() && vault_result.kout_bits_total.is_finite() {
                    Some((taxed_bits + vault_result.kout_bits_total).max(0.0).ceil() as u64)
                } else {
                    None
                };
            let principal_fuel = if fuel_total > 0 {
                Some(fuel_total)
            } else {
                None
            };
            let principal_mem_pages = if vault_result.max_memory_pages > 0 {
                Some(vault_result.max_memory_pages)
            } else {
                None
            };
            self.charge_principal_credit(
                &principal_id,
                principal_k_bits,
                principal_fuel,
                principal_mem_pages,
            )?;
            let (e_value, eprocess_kind_id) =
                compute_nullspec_e_value(&contract, &vault_result.oracle_buckets)?;
            let canary_key = Self::canary_key(&claim.claim_name, &claim.holdout_ref);
            let mut canary_state = {
                let mut canary_states = self.state.canary_states.lock();
                if !canary_states.contains_key(&canary_key) {
                    let initial = CanaryState::new(self.canary_config)
                        .map_err(|_| Status::internal("canary state init failed"))?;
                    canary_states.insert(canary_key.clone(), initial);
                }
                canary_states
                    .get(&canary_key)
                    .cloned()
                    .ok_or_else(|| Status::internal("missing canary state"))?
            };
            for b in &vault_result.oracle_buckets {
                let bucket = usize::try_from(*b)
                    .map_err(|_| Status::failed_precondition("bucket overflow"))?;
                canary_state
                    .update_with_bucket(&contract, bucket, current_epoch)
                    .map_err(|_| Status::failed_precondition("canary drift update failed"))?;
            }
            {
                let mut canary_states = self.state.canary_states.lock();
                canary_states.insert(canary_key, canary_state.clone());
            }
            claim
                .ledger
                .settle_e_value(e_value, "decision", json!({"e_value_total": e_value}))
                .map_err(|_| Status::invalid_argument("invalid e-value"))?;
            self.transition_claim(
                claim,
                ClaimState::Settled,
                taxed_bits + vault_result.kout_bits_total,
                e_value,
                None,
            )?;
            let ledger_numeric_guard_failure = claim.ledger.certification_guard_failure();
            let can_certify = claim.ledger.can_certify();
            let mut decision = if claim.ledger.is_frozen()
                || ledger_numeric_guard_failure.is_some()
                || claim.lane == Lane::Heavy
                || physhir_mismatch
                || magnitude_envelope_violation
            {
                pb::Decision::Defer as i32
            } else if can_certify {
                pb::Decision::Approve as i32
            } else {
                pb::Decision::Reject as i32
            };
            if canary_state.drift_frozen {
                decision = pb::Decision::Reject as i32;
                self.append_canary_incident(
                    claim,
                    "canary_drift_frozen",
                    canary_state.e_drift,
                    canary_state.barrier,
                )?;
            }
            let mut reason_codes = match decision {
                x if x == pb::Decision::Approve as i32 => vec![1],
                x if x == pb::Decision::Defer as i32 => {
                    self.telemetry.record_reject("defer");
                    vec![3]
                }
                _ => {
                    self.telemetry.record_reject("reject");
                    vec![2]
                }
            };
            if canary_state.drift_frozen {
                reason_codes.push(91);
            }
            if physhir_mismatch {
                reason_codes.push(9104);
            }
            if magnitude_envelope_violation {
                reason_codes.push(MAGNITUDE_ENVELOPE_REASON_CODE);
            }
            if ledger_numeric_guard_failure.is_some() {
                reason_codes.push(LEDGER_NUMERIC_GUARD_REASON_CODE);
            }
            let oracle_input = policy_oracle_input_json(
                claim,
                &vault_result,
                fuel_total,
                &claim.ledger,
                &canonical_output,
                &reason_codes,
            )?;
            let mut policy_receipts: Vec<PolicyOracleReceipt> = Vec::new();
            if oracle_ttl_expired {
                reason_codes.push(ORACLE_EXPIRED_REASON_CODE);
                policy_receipts.push(PolicyOracleReceipt {
                    oracle_id: "oracle_ttl".to_string(),
                    manifest_hash_hex: hex::encode([0_u8; 32]),
                    wasm_hash_hex: hex::encode([0_u8; 32]),
                    decision: if oracle_ttl_escalated {
                        "defer".to_string()
                    } else {
                        "reject".to_string()
                    },
                    reason_code: if oracle_ttl_escalated {
                        ORACLE_TTL_ESCALATED_REASON_CODE
                    } else {
                        ORACLE_EXPIRED_REASON_CODE
                    },
                });
            }
            let mut oracle_decision = PolicyOracleDecision::Pass;
            for oracle in self.policy_oracles.iter() {
                match oracle.evaluate(&oracle_input) {
                    Ok((d, receipt)) => {
                        if d != PolicyOracleDecision::Pass {
                            reason_codes.push(receipt.reason_code);
                        }
                        if d == PolicyOracleDecision::Reject {
                            oracle_decision = PolicyOracleDecision::Reject;
                        } else if d == PolicyOracleDecision::DeferToHeavy
                            && oracle_decision != PolicyOracleDecision::Reject
                        {
                            oracle_decision = PolicyOracleDecision::DeferToHeavy;
                        }
                        policy_receipts.push(receipt);
                    }
                    Err(_) => {
                        oracle_decision = PolicyOracleDecision::DeferToHeavy;
                        let receipt = oracle.fail_closed_receipt();
                        reason_codes.push(receipt.reason_code);
                        policy_receipts.push(receipt);
                    }
                }
            }
            if oracle_decision == PolicyOracleDecision::Reject {
                decision = pb::Decision::Reject as i32;
            } else if oracle_decision == PolicyOracleDecision::DeferToHeavy {
                decision = pb::Decision::Defer as i32;
            }
            if decision != pb::Decision::Approve as i32 {
                let clamped = e_value.min(1.0);
                if clamped < e_value {
                    claim
                        .ledger
                        .scale_wealth(clamped / e_value)
                        .map_err(|_| Status::internal("failed to clamp wealth"))?;
                }
            }
            if decision == pb::Decision::Defer as i32 {
                self.transition_claim(claim, ClaimState::Frozen, 0.0, 0.0, None)?;
            } else if decision == pb::Decision::Approve as i32 {
                self.transition_claim(claim, ClaimState::Certified, 0.0, 0.0, None)?;
            } else {
                self.transition_claim(claim, ClaimState::Revoked, 0.0, 0.0, None)?;
            }
            reason_codes.sort_unstable();
            reason_codes.dedup();
            let e_value = if decision == pb::Decision::Approve as i32 {
                e_value
            } else {
                e_value.min(1.0)
            };
            let canonical_output = kernel_structured_output(
                &claim.output_schema_id,
                &canonical_output,
                decision,
                &reason_codes,
                e_value,
            )?;
            let mut capsule = ClaimCapsule::new(
                hex::encode(claim.claim_id),
                hex::encode(claim.topic_id),
                claim.output_schema_id.clone(),
                claim
                    .artifacts
                    .iter()
                    .map(|(hash, kind)| ManifestEntry {
                        kind: kind.clone(),
                        hash_hex: hex::encode(hash),
                    })
                    .collect(),
                claim.dependency_capsule_hashes.clone(),
                &canonical_output,
                &claim.wasm_module,
                &claim.holdout_handle_id,
                &claim.ledger,
                e_value,
                claim.state == ClaimState::Certified,
                decision,
                reason_codes.clone(),
                policy_receipts.into_iter().map(Into::into).collect(),
                &trace_hash,
                claim.holdout_ref.clone(),
                format!("deterministic-kernel-{}", env!("CARGO_PKG_VERSION")),
                "aspec.v1".to_string(),
                "evidenceos.v1".to_string(),
                fuel_total as f64,
            );
            self.populate_tee_attestation(&mut capsule, &claim.wasm_module)?;
            capsule.nullspec_id_hex = Some(hex::encode(contract.nullspec_id));
            capsule.oracle_resolution_hash_hex = Some(hex::encode(contract.oracle_resolution_hash));
            capsule.eprocess_kind = Some(eprocess_kind_id);
            capsule.nullspec_contract_hash_hex =
                Some(hex::encode(contract.compute_id().map_err(|_| {
                    Status::internal("nullspec id compute failed")
                })?));
            capsule.semantic_hash_hex = Some(hex::encode(claim.semantic_hash));
            capsule.physhir_hash_hex = Some(hex::encode(claim.phys_hir_hash));
            capsule.lineage_root_hash_hex = Some(hex::encode(claim.lineage_root_hash));
            capsule.output_schema_id_hash_hex = Some(hex::encode(claim.output_schema_id_hash));
            capsule.holdout_handle_hash_hex = Some(hex::encode(claim.holdout_handle_hash));
            capsule.disagreement_score = Some(claim.disagreement_score);
            capsule.semantic_physhir_distance_bits = Some(claim.semantic_physhir_distance_bits);
            capsule.escalate_to_heavy = Some(claim.escalate_to_heavy);
            capsule.topic_oracle_receipt =
                claim
                    .topic_oracle_receipt
                    .as_ref()
                    .map(|receipt| TopicOracleReceiptLike {
                        claim_manifest_hash_hex: hex::encode(receipt.claim_manifest_hash),
                        semantic_hash_hex: hex::encode(receipt.semantic_hash),
                        model_id: receipt.model_id.clone(),
                        timestamp_unix: receipt.timestamp_unix,
                        signature_hex: hex::encode(&receipt.signature),
                    });
            capsule.trial_commitment_hash_hex = Some(hex::encode(claim.trial_commitment_hash));
            if let Some(assignment) = claim.trial_assignment.as_ref() {
                capsule.trial_commitment_schema_version =
                    Some(u32::from(TRIAL_COMMITMENT_SCHEMA_VERSION));
                capsule.trial_arm_id = Some(u32::from(assignment.arm_id));
                capsule.trial_intervention_id = Some(assignment.intervention_id.clone());
                capsule.trial_intervention_version = Some(assignment.intervention_version.clone());
                capsule.trial_arm_parameters_hash_hex =
                    Some(hex::encode(assignment.arm_parameters_hash));
                capsule.trial_nonce_hex = Some(hex::encode(assignment.trial_nonce));
                let trial_config_hash_hex = self.trial_config_hash.map(hex::encode);
                capsule.trial_config_hash_hex = trial_config_hash_hex.clone();
                capsule.trial = Some(TrialMetadata {
                    intervention_id: Some(assignment.intervention_id.clone()),
                    intervention_version: Some(assignment.intervention_version.clone()),
                    arm_parameters_hash_hex: Some(hex::encode(assignment.arm_parameters_hash)),
                    arm_id: Some(u32::from(assignment.arm_id)),
                    trial_nonce_hex: Some(hex::encode(assignment.trial_nonce)),
                    trial_config_hash_hex,
                    allocator_snapshot_hash_hex: assignment
                        .allocator_snapshot_hash
                        .map(hex::encode),
                });
            }
            capsule.state = if claim.state == ClaimState::Certified {
                CoreClaimState::Certified
            } else {
                CoreClaimState::Settled
            };
            let capsule_bytes = capsule
                .to_json_bytes()
                .map_err(|_| Status::internal("capsule serialization failed"))?;
            let capsule_hash = decode_hex_hash32(
                &capsule
                    .capsule_hash_hex()
                    .map_err(|_| Status::internal("capsule hashing failed"))?,
                "capsule_hash",
            )?;
            let etl_index = if self.offline_settlement_ingest {
                let etl = self.state.etl.lock();
                let sth_hash_hex = hex::encode(etl.root_hash());
                drop(etl);
                let proposal = UnsignedSettlementProposal {
                    schema_version: 1,
                    claim_id_hex: hex::encode(claim.claim_id),
                    claim_state: Self::state_name(claim.state).to_string(),
                    epoch: claim.epoch_counter,
                    etl_index: 0,
                    sth_hash_hex,
                    decision,
                    reason_codes: reason_codes.clone(),
                    capsule_hash_hex: hex::encode(capsule_hash),
                };
                write_unsigned_proposal(&self.state.data_path, &proposal)
                    .map_err(|_| Status::internal("offline settlement spool write failed"))?;
                0
            } else {
                let mut etl = self.state.etl.lock();
                let (idx, _) = etl
                    .append(&capsule_bytes)
                    .map_err(|_| Status::internal("etl append failed"))?;
                etl.sync_data()
                    .map_err(|_| Status::internal("etl sync failed"))?;
                idx
            };
            claim.last_decision = Some(decision);
            claim.last_capsule_hash = Some(capsule_hash);
            claim.capsule_bytes = Some(capsule_bytes.clone());
            claim.etl_index = if self.offline_settlement_ingest {
                None
            } else {
                Some(etl_index)
            };
            (
                claim.state,
                decision,
                reason_codes,
                canonical_output,
                e_value,
                claim.state == ClaimState::Certified,
                capsule_hash,
                etl_index,
                claim.claim_id,
                capsule_bytes,
                claim.etl_index,
            )
        };
        let pending = PendingMutation::Execute {
            claim_id,
            state,
            decision,
            capsule_hash,
            capsule_bytes,
            etl_index: stored_etl_index,
        };
        persist_pending_mutation(&self.state, &pending)?;
        maybe_abort_failpoint("after_etl_append_execute_claim_v2");
        persist_all_with_trial_router(&self.state, Some(&self.trial_router))?;
        clear_pending_mutation(&self.state, claim_id)?;

        let response = pb::ExecuteClaimV2Response {
            state: state.to_proto(),
            decision,
            reason_codes,
            canonical_output,
            e_value,
            certified,
            capsule_hash: capsule_hash.to_vec(),
            etl_index,
        };
        if let Err(status) = self.idempotency_store_success(idempotency_context, &response) {
            return Err(status);
        }
        Ok(Response::new(response))
    }

    async fn get_capsule(
        &self,
        request: Request<pb::GetCapsuleRequest>,
    ) -> Result<Response<pb::GetCapsuleResponse>, Status> {
        let (metadata, extensions, req) = decompose_request(request);
        let resp = <Self as EvidenceOsV2>::fetch_capsule(
            self,
            recompose_request(
                metadata,
                extensions,
                pb::FetchCapsuleRequest {
                    claim_id: req.claim_id,
                },
            ),
        )
        .await?
        .into_inner();
        Ok(Response::new(pb::GetCapsuleResponse {
            capsule_bytes: resp.capsule_bytes,
            capsule_hash: resp.capsule_hash,
            etl_index: resp.etl_index,
        }))
    }

    async fn get_public_key(
        &self,
        request: Request<pb::GetPublicKeyRequest>,
    ) -> Result<Response<pb::GetPublicKeyResponse>, Status> {
        let req = request.into_inner();
        let requested_key_id = if req.key_id.is_empty() {
            self.state.active_key_id
        } else {
            parse_hash32(&req.key_id, "key_id")?
        };
        let signing_key = self
            .state
            .keyring
            .get(&requested_key_id)
            .ok_or_else(|| Status::not_found("key not found"))?;
        Ok(Response::new(pb::GetPublicKeyResponse {
            ed25519_public_key: signing_key.verifying_key().to_bytes().to_vec(),
            key_id: requested_key_id.to_vec(),
        }))
    }

    async fn get_signed_tree_head(
        &self,
        _request: Request<pb::GetSignedTreeHeadRequest>,
    ) -> Result<Response<pb::GetSignedTreeHeadResponse>, Status> {
        let etl = self.state.etl.lock();
        let signing_key = self.active_signing_key()?;
        let sth = build_signed_tree_head(&etl, signing_key, self.state.active_key_id);
        Ok(Response::new(pb::GetSignedTreeHeadResponse {
            tree_size: sth.tree_size,
            root_hash: sth.root_hash,
            signature: sth.signature,
            key_id: sth.key_id,
        }))
    }

    async fn get_inclusion_proof(
        &self,
        request: Request<pb::GetInclusionProofRequest>,
    ) -> Result<Response<pb::GetInclusionProofResponse>, Status> {
        let caller = Self::caller_identity(request.metadata());
        Self::require_auditor_role(&caller, "GetInclusionProof")?;
        let req = request.into_inner();
        let etl = self.state.etl.lock();
        let leaf_hash = etl
            .leaf_hash_at(req.leaf_index)
            .map_err(|_| Status::not_found("leaf index not found"))?;
        let proof = etl
            .inclusion_proof(req.leaf_index)
            .map_err(|_| Status::not_found("leaf index not found"))?;
        Ok(Response::new(pb::GetInclusionProofResponse {
            leaf_hash: leaf_hash.to_vec(),
            sibling_hashes: proof.into_iter().map(|h| h.to_vec()).collect(),
            root_hash: etl.root_hash().to_vec(),
        }))
    }

    async fn get_consistency_proof(
        &self,
        request: Request<pb::GetConsistencyProofRequest>,
    ) -> Result<Response<pb::GetConsistencyProofResponse>, Status> {
        let caller = Self::caller_identity(request.metadata());
        Self::require_auditor_role(&caller, "GetConsistencyProof")?;
        let req = request.into_inner();
        if req.first_tree_size > req.second_tree_size {
            return Err(Status::invalid_argument(
                "first_tree_size must be <= second_tree_size",
            ));
        }
        let etl = self.state.etl.lock();
        let first_root = etl
            .root_at_size(req.first_tree_size)
            .map_err(|_| Status::invalid_argument("first_tree_size out of bounds"))?;
        let second_root = etl
            .root_at_size(req.second_tree_size)
            .map_err(|_| Status::invalid_argument("second_tree_size out of bounds"))?;
        let proof = etl
            .consistency_proof(req.first_tree_size, req.second_tree_size)
            .map_err(|_| Status::invalid_argument("invalid tree size pair"))?;
        let consistent = verify_consistency_proof(
            &first_root,
            &second_root,
            req.first_tree_size as usize,
            req.second_tree_size as usize,
            &proof,
        );
        Ok(Response::new(pb::GetConsistencyProofResponse {
            consistent,
            first_root_hash: first_root.to_vec(),
            second_root_hash: second_root.to_vec(),
        }))
    }

    async fn get_revocation_feed(
        &self,
        request: Request<pb::GetRevocationFeedRequest>,
    ) -> Result<Response<pb::GetRevocationFeedResponse>, Status> {
        let _ = request;
        let response = <Self as EvidenceOsV2>::watch_revocations(
            self,
            Request::new(pb::WatchRevocationsRequest {}),
        )
        .await?;
        let mut stream = response.into_inner();
        let item = stream
            .next()
            .await
            .ok_or_else(|| Status::not_found("no revocations"))??;
        Ok(Response::new(pb::GetRevocationFeedResponse {
            entries: item.entries,
            signature: item.signature,
            key_id: item.key_id,
        }))
    }

    async fn fetch_capsule(
        &self,
        request: Request<pb::FetchCapsuleRequest>,
    ) -> Result<Response<pb::FetchCapsuleResponse>, Status> {
        let caller = Self::caller_identity(request.metadata());
        Self::require_auditor_role(&caller, "FetchCapsule")?;
        let claim_id = parse_hash32(&request.into_inner().claim_id, "claim_id")?;
        let claims = self.state.claims.lock();
        let claim = claims
            .get(&claim_id)
            .ok_or_else(|| Status::not_found("claim not found"))?;
        Self::enforce_claim_access(&caller, claim, "FetchCapsuleV2")?;
        let capsule_bytes = claim
            .capsule_bytes
            .clone()
            .ok_or_else(|| Status::failed_precondition("capsule not available"))?;
        let capsule_hash = claim
            .last_capsule_hash
            .ok_or_else(|| Status::failed_precondition("capsule hash unavailable"))?;
        let etl_index = claim
            .etl_index
            .ok_or_else(|| Status::failed_precondition("etl index unavailable"))?;
        drop(claims);

        let etl = self.state.etl.lock();
        let tree_size = etl.tree_size();
        let root_hash = etl.root_hash();
        let leaf_hash = etl
            .leaf_hash_at(etl_index)
            .map_err(|_| Status::not_found("leaf index not found"))?;
        let audit_path = etl
            .inclusion_proof(etl_index)
            .map_err(|_| Status::not_found("leaf index not found"))?;
        let consistency_path = etl
            .consistency_proof(etl_index + 1, tree_size)
            .map_err(|_| Status::internal("consistency proof failed"))?
            .into_iter()
            .map(|h| h.to_vec())
            .collect();

        Ok(Response::new(pb::FetchCapsuleResponse {
            capsule_bytes,
            capsule_hash: capsule_hash.to_vec(),
            etl_index,
            signed_tree_head: Some(build_signed_tree_head(
                &etl,
                self.active_signing_key()?,
                self.state.active_key_id,
            )),
            inclusion_proof: Some(pb::MerkleInclusionProof {
                leaf_hash: leaf_hash.to_vec(),
                leaf_index: etl_index,
                tree_size,
                audit_path: audit_path.into_iter().map(|h| h.to_vec()).collect(),
            }),
            consistency_proof: Some(pb::MerkleConsistencyProof {
                old_tree_size: etl_index + 1,
                new_tree_size: tree_size,
                path: consistency_path,
            }),
            root_hash: root_hash.to_vec(),
            tree_size,
        }))
    }

    async fn revoke_claim(
        &self,
        request: Request<pb::RevokeClaimRequest>,
    ) -> Result<Response<pb::RevokeClaimResponse>, Status> {
        let caller = Self::caller_identity(request.metadata());
        let principal_id = caller.principal_id.clone();
        let request_id = Self::request_id_from_metadata(request.metadata())?;
        let req_msg = request.get_ref().clone();
        let idempotency = self
            .idempotency_lookup::<pb::RevokeClaimRequest, pb::RevokeClaimResponse>(
                "/evidenceos.v2.EvidenceOS/RevokeClaimV2",
                &principal_id,
                &request_id,
                &req_msg,
            )?;
        let idempotency_context = match idempotency {
            IdempotencyLookup::Cached(cached) => return Ok(Response::new(cached)),
            IdempotencyLookup::Miss(ctx) => ctx,
        };
        let req = request.into_inner();
        if req.reason.is_empty() || req.reason.len() > 256 {
            return Err(Status::invalid_argument("reason must be in [1,256]"));
        }
        let claim_id = parse_hash32(&req.claim_id, "claim_id")?;
        let capsule_hash = {
            let claims = self.state.claims.lock();
            let claim = claims
                .get(&claim_id)
                .ok_or_else(|| Status::not_found("claim not found"))?;
            Self::enforce_claim_access(&caller, claim, "RevokeClaimV2")?;
            claim
                .last_capsule_hash
                .ok_or_else(|| Status::failed_precondition("capsule hash unavailable"))?
        };
        {
            let mut claims = self.state.claims.lock();
            let claim = claims
                .get_mut(&claim_id)
                .ok_or_else(|| Status::not_found("claim not found"))?;
            claim.state = ClaimState::Revoked;
        }
        let timestamp_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| Status::internal("system clock before unix epoch"))?
            .as_secs();

        let mut tainted_claim_ids = Vec::new();
        {
            let mut etl = self.state.etl.lock();
            etl.revoke(&hex::encode(capsule_hash), &req.reason)
                .map_err(|_| Status::internal("etl revoke failed"))?;
            etl.sync_data()
                .map_err(|_| Status::internal("etl sync failed"))?;
            let tainted = etl.taint_descendants(&hex::encode(capsule_hash));
            if !tainted.is_empty() {
                let mut claims = self.state.claims.lock();
                for claim in claims.values_mut() {
                    if let Some(hash) = claim.last_capsule_hash {
                        let hash_hex = hex::encode(hash);
                        if tainted.iter().any(|t| t == &hash_hex) {
                            claim.state = ClaimState::Tainted;
                            tainted_claim_ids.push(claim.claim_id);
                        }
                    }
                }
            }
        }

        self.state
            .revocations
            .lock()
            .push((capsule_hash, timestamp_unix, req.reason.clone()));

        let pending = PendingMutation::Revoke {
            claim_id,
            capsule_hash,
            reason: req.reason.clone(),
            timestamp_unix,
            tainted_claim_ids,
            etl_applied: true,
        };
        persist_pending_mutation(&self.state, &pending)?;
        maybe_abort_failpoint("after_etl_append_revoke_claim");
        persist_all_with_trial_router(&self.state, Some(&self.trial_router))?;
        clear_pending_mutation(&self.state, claim_id)?;

        let message = {
            let etl = self.state.etl.lock();
            build_revocations_snapshot(
                self.active_signing_key()?,
                self.state.active_key_id,
                vec![(capsule_hash, timestamp_unix, req.reason)],
                build_signed_tree_head(&etl, self.active_signing_key()?, self.state.active_key_id),
            )?
        };

        let subscribers = self.state.revocation_subscribers.lock().clone();
        for tx in subscribers {
            let _ = tx.try_send(message.clone());
        }

        let response = pb::RevokeClaimResponse {
            state: pb::ClaimState::Revoked as i32,
            timestamp_unix,
        };
        self.idempotency_store_success(idempotency_context, &response)?;
        Ok(Response::new(response))
    }

    async fn grant_credit(
        &self,
        request: Request<pb::GrantCreditRequest>,
    ) -> Result<Response<pb::GrantCreditResponse>, Status> {
        let operator_principal = Self::principal_id_from_metadata(request.metadata());
        self.require_operator(&operator_principal)?;
        let req = request.into_inner();
        validate_required_str_field(&req.principal_id, "principal_id", MAX_PRINCIPAL_ID_LEN)?;
        validate_required_str_field(&req.reason, "reason", MAX_CREDIT_REASON_LEN)?;
        if req.amount == 0 {
            return Err(Status::invalid_argument("amount must be > 0"));
        }
        self.admission_provider
            .admit(&req.principal_id, req.amount)?;
        let default_limit = self.default_credit_limit_for(&req.principal_id);
        let mut store = self.state.account_store.lock();
        let balance = store.grant_credit(&req.principal_id, req.amount, default_limit)?;
        Ok(Response::new(pb::GrantCreditResponse {
            credit_balance: balance,
        }))
    }

    async fn set_credit_limit(
        &self,
        request: Request<pb::SetCreditLimitRequest>,
    ) -> Result<Response<pb::SetCreditLimitResponse>, Status> {
        let operator_principal = Self::principal_id_from_metadata(request.metadata());
        self.require_operator(&operator_principal)?;
        let req = request.into_inner();
        validate_required_str_field(&req.principal_id, "principal_id", MAX_PRINCIPAL_ID_LEN)?;
        self.admission_provider
            .admit(&req.principal_id, req.limit)?;
        let default_limit = self.default_credit_limit_for(&req.principal_id);
        let mut store = self.state.account_store.lock();
        let limit = store.set_credit_limit(&req.principal_id, req.limit, default_limit)?;
        Ok(Response::new(pb::SetCreditLimitResponse {
            credit_limit: limit,
        }))
    }

    async fn set_holdout_pool_budgets(
        &self,
        request: Request<pb::SetHoldoutPoolBudgetsRequest>,
    ) -> Result<Response<pb::SetHoldoutPoolBudgetsResponse>, Status> {
        let caller = Self::caller_identity(request.metadata());
        Self::require_auditor_role(&caller, "SetHoldoutPoolBudgets")?;
        let req = request.into_inner();
        validate_required_str_field(&req.holdout_id, "holdout_id", 128)?;
        let holdout_id = decode_hex_hash32(&req.holdout_id, "holdout_id")?;
        let scope = HoldoutPoolScope::parse(req.scope.trim())?;
        let next_k_bits = req.new_k_bits_budget;
        let next_access_credit = req.new_access_credit_budget;
        if let Some(v) = next_k_bits {
            Self::validate_budget_value(v, "new_k_bits_budget")?;
        }
        if let Some(v) = next_access_credit {
            Self::validate_budget_value(v, "new_access_credit_budget")?;
        }
        let mut touched = 0usize;
        {
            let mut holdout_pools = self.state.holdout_pools.lock();
            for (key, pool) in holdout_pools.iter_mut() {
                if key.holdout_id != holdout_id {
                    continue;
                }
                let scope_match = match scope {
                    HoldoutPoolScope::Global => key.principal_id.is_none(),
                    HoldoutPoolScope::PerPrincipal => key.principal_id.is_some(),
                    HoldoutPoolScope::Both => true,
                };
                if !scope_match {
                    continue;
                }
                if let Some(v) = next_k_bits {
                    pool.k_bits_budget = v;
                }
                if let Some(v) = next_access_credit {
                    pool.access_credit_budget = v;
                }
                if pool.k_bits_spent <= pool.k_bits_budget + f64::EPSILON
                    && pool.access_credit_spent <= pool.access_credit_budget + f64::EPSILON
                {
                    pool.frozen = false;
                }
                touched += 1;
            }
        }
        if touched == 0 {
            return Err(Status::not_found("holdout budget pool not found"));
        }
        persist_all_with_trial_router(&self.state, Some(&self.trial_router))?;
        Ok(Response::new(pb::SetHoldoutPoolBudgetsResponse {
            budgets: Some(pb::HoldoutPoolBudgets {
                holdout_id: req.holdout_id,
                scope: req.scope,
                k_bits_budget: next_k_bits,
                access_credit_budget: next_access_credit,
            }),
        }))
    }

    async fn get_holdout_pool_budgets(
        &self,
        request: Request<pb::GetHoldoutPoolBudgetsRequest>,
    ) -> Result<Response<pb::GetHoldoutPoolBudgetsResponse>, Status> {
        let caller = Self::caller_identity(request.metadata());
        Self::require_auditor_role(&caller, "GetHoldoutPoolBudgets")?;
        let req = request.into_inner();
        validate_required_str_field(&req.holdout_id, "holdout_id", 128)?;
        let holdout_id = decode_hex_hash32(&req.holdout_id, "holdout_id")?;
        let scope = HoldoutPoolScope::parse(req.scope.trim())?;
        let holdout_pools = self.state.holdout_pools.lock();
        let mut pools = holdout_pools.iter().filter(|(key, _)| {
            key.holdout_id == holdout_id
                && match scope {
                    HoldoutPoolScope::Global => key.principal_id.is_none(),
                    HoldoutPoolScope::PerPrincipal => key.principal_id.is_some(),
                    HoldoutPoolScope::Both => true,
                }
        });
        let first = pools
            .next()
            .map(|(_, pool)| pool)
            .ok_or_else(|| Status::not_found("holdout budget pool not found"))?;
        Ok(Response::new(pb::GetHoldoutPoolBudgetsResponse {
            budgets: Some(pb::HoldoutPoolBudgets {
                holdout_id: req.holdout_id,
                scope: req.scope,
                k_bits_budget: Some(first.k_bits_budget),
                access_credit_budget: Some(first.access_credit_budget),
            }),
        }))
    }

    async fn watch_revocations(
        &self,
        _request: Request<pb::WatchRevocationsRequest>,
    ) -> Result<Response<Self::WatchRevocationsStream>, Status> {
        let (tx, rx) = mpsc::channel(8);
        self.state.revocation_subscribers.lock().push(tx.clone());

        let entries_raw = self.state.revocations.lock().clone();
        let etl = self.state.etl.lock();
        let snapshot = build_revocations_snapshot(
            self.active_signing_key()?,
            self.state.active_key_id,
            entries_raw,
            build_signed_tree_head(&etl, self.active_signing_key()?, self.state.active_key_id),
        )?;
        let _ = tx.try_send(snapshot);

        Ok(Response::new(Box::pin(ReceiverStream::new(rx).map(Ok))))
    }
}
