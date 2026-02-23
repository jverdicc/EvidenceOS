use super::*;

const IDEMPOTENCY_DIR_NAME: &str = "idempotency";
const IDEMPOTENCY_REQUEST_HASH_DOMAIN: &[u8] = b"evidenceos:idempotency:request:v1";

#[derive(Debug)]
pub(super) enum IdempotencyLookup<ResponseMessage> {
    Miss(IdempotencyContext),
    Cached(ResponseMessage),
}

impl EvidenceOsService {
    pub(super) fn idempotency_lookup<RequestMessage, ResponseMessage>(
        &self,
        method: &'static str,
        principal_id: &str,
        request_id: &str,
        request: &RequestMessage,
    ) -> Result<IdempotencyLookup<ResponseMessage>, Status>
    where
        RequestMessage: Message,
        ResponseMessage: Message + Default,
    {
        let request_hash = idempotency_request_hash(method, request)?;
        let now = Instant::now();
        let key = (
            principal_id.to_string(),
            method.to_string(),
            request_id.to_string(),
        );
        let mut cache = self.state.idempotency.lock();
        cache.retain(|_, entry| match entry {
            IdempotencyEntry::InFlight { expires_at } => *expires_at > now,
            IdempotencyEntry::Ready { expires_at, .. } => *expires_at > now,
        });
        if let Some(entry) = cache.get(&key) {
            return match entry {
                IdempotencyEntry::InFlight { .. } => Err(Status::aborted(
                    "request with x-request-id already in progress",
                )),
                IdempotencyEntry::Ready { record, .. } => {
                    if record.request_hash != request_hash {
                        return Err(Status::already_exists(
                            "x-request-id reused with different request payload",
                        ));
                    }
                    if record.status_code == Code::Ok as u32 {
                        let response = ResponseMessage::decode(record.response_bytes.as_slice())
                            .map_err(|_| Status::internal("idempotency decode failure"))?;
                        Ok(IdempotencyLookup::Cached(response))
                    } else {
                        let code = Code::from_i32(record.status_code as i32);
                        Err(Status::new(
                            code,
                            record
                                .status_message
                                .clone()
                                .unwrap_or_else(|| "idempotent cached error".to_string()),
                        ))
                    }
                }
            };
        }

        let expires_at = now + IDEMPOTENCY_TTL;
        cache.insert(key.clone(), IdempotencyEntry::InFlight { expires_at });
        drop(cache);

        let context = IdempotencyContext { key, request_hash };
        Ok(IdempotencyLookup::Miss(context))
    }

    pub(super) fn idempotency_store_success<ResponseMessage>(
        &self,
        context: IdempotencyContext,
        response: &ResponseMessage,
    ) -> Result<(), Status>
    where
        ResponseMessage: Message,
    {
        let mut response_bytes = Vec::new();
        response
            .encode(&mut response_bytes)
            .map_err(|_| Status::internal("idempotency encode failure"))?;
        let record = IdempotencyRecord {
            request_hash: context.request_hash,
            status_code: Code::Ok as u32,
            status_message: None,
            response_bytes,
            created_at_unix_ms: current_time_unix_ms()?,
        };
        self.idempotency_store_record(context, record)
    }

    fn idempotency_store_record(
        &self,
        context: IdempotencyContext,
        record: IdempotencyRecord,
    ) -> Result<(), Status> {
        write_idempotency_record(&self.state.data_path, &context.key, &record)?;
        let mut cache = self.state.idempotency.lock();
        cache.insert(
            context.key,
            IdempotencyEntry::Ready {
                expires_at: Instant::now() + IDEMPOTENCY_TTL,
                record,
            },
        );
        Ok(())
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

pub(super) fn load_idempotency_records(state: &ServerState) -> Result<(), Status> {
    let dir = idempotency_dir(&state.data_path);
    if !dir.exists() {
        return Ok(());
    }
    let now_ms = current_time_unix_ms()?;
    let mut cache = state.idempotency.lock();
    for path in std::fs::read_dir(&dir)
        .map_err(|_| Status::internal("read idempotency directory failed"))?
        .map(|entry| {
            entry
                .map(|v| v.path())
                .map_err(|_| Status::internal("read idempotency directory entry failed"))
        })
        .collect::<Result<Vec<_>, _>>()?
    {
        if !path.is_file() {
            continue;
        }
        let Some(file_name) = path.file_name().and_then(|v| v.to_str()) else {
            continue;
        };
        if !file_name.ends_with(".json") {
            continue;
        }
        let bytes =
            std::fs::read(&path).map_err(|_| Status::internal("read idempotency file failed"))?;
        let persisted: PersistedIdempotencyRecord = serde_json::from_slice(&bytes)
            .map_err(|_| Status::internal("decode idempotency file failed"))?;
        let age_ms = now_ms.saturating_sub(persisted.record.created_at_unix_ms);
        let ttl_ms = IDEMPOTENCY_TTL.as_millis() as u64;
        if age_ms > ttl_ms {
            remove_file_durable(&path)?;
            continue;
        }
        cache.insert(
            (
                persisted.principal_id,
                persisted.rpc_method,
                persisted.request_id,
            ),
            IdempotencyEntry::Ready {
                expires_at: Instant::now() + Duration::from_millis(ttl_ms - age_ms),
                record: persisted.record,
            },
        );
    }
    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedIdempotencyRecord {
    principal_id: String,
    rpc_method: String,
    request_id: String,
    record: IdempotencyRecord,
}

fn write_idempotency_record(
    data_path: &Path,
    key: &(String, String, String),
    record: &IdempotencyRecord,
) -> Result<(), Status> {
    let dir = idempotency_dir(data_path);
    ensure_directory_durable(&dir)?;
    let persisted = PersistedIdempotencyRecord {
        principal_id: key.0.clone(),
        rpc_method: key.1.clone(),
        request_id: key.2.clone(),
        record: record.clone(),
    };
    let bytes = serde_json::to_vec_pretty(&persisted)
        .map_err(|_| Status::internal("serialize idempotency record failed"))?;
    write_file_atomic_durable(
        &idempotency_path(data_path, key),
        &bytes,
        "write idempotency record failed",
    )
}

fn idempotency_request_hash<RequestMessage>(
    method: &'static str,
    request: &RequestMessage,
) -> Result<[u8; 32], Status>
where
    RequestMessage: Message,
{
    let mut req_bytes = Vec::new();
    request
        .encode(&mut req_bytes)
        .map_err(|_| Status::internal("request hash encode failure"))?;
    let mut payload = Vec::with_capacity(method.len() + 1 + req_bytes.len());
    payload.extend_from_slice(method.as_bytes());
    payload.push(0);
    payload.extend_from_slice(&req_bytes);
    Ok(sha256_domain(IDEMPOTENCY_REQUEST_HASH_DOMAIN, &payload))
}

fn idempotency_dir(data_path: &Path) -> PathBuf {
    data_path.join(IDEMPOTENCY_DIR_NAME)
}

fn idempotency_path(data_path: &Path, key: &(String, String, String)) -> PathBuf {
    let mut h = Sha256::new();
    h.update(key.0.as_bytes());
    h.update([0]);
    h.update(key.1.as_bytes());
    h.update([0]);
    h.update(key.2.as_bytes());
    let digest = h.finalize();
    idempotency_dir(data_path).join(format!("{}.json", hex::encode(digest)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn idempotency_same_payload_returns_cached_response() {
        let dir = TempDir::new().expect("tmp");
        let telemetry = Arc::new(Telemetry::new().expect("telemetry"));
        let svc = EvidenceOsService::build_with_options(
            dir.path().to_str().expect("utf8"),
            false,
            telemetry,
        )
        .expect("service");

        let req = pb::SetCreditLimitRequest {
            principal_id: "p1".to_string(),
            limit: 42,
        };
        let lookup = svc
            .idempotency_lookup::<pb::SetCreditLimitRequest, pb::SetCreditLimitResponse>(
                "/evidenceos.v2.EvidenceOS/SetCreditLimit",
                "principal-a",
                "req-1",
                &req,
            )
            .expect("lookup");
        let ctx = match lookup {
            IdempotencyLookup::Miss(ctx) => ctx,
            IdempotencyLookup::Cached(_) => panic!("expected miss"),
        };
        let response = pb::SetCreditLimitResponse { credit_limit: 42 };
        svc.idempotency_store_success(ctx, &response)
            .expect("store");

        let cached = svc
            .idempotency_lookup::<pb::SetCreditLimitRequest, pb::SetCreditLimitResponse>(
                "/evidenceos.v2.EvidenceOS/SetCreditLimit",
                "principal-a",
                "req-1",
                &req,
            )
            .expect("lookup cached");
        match cached {
            IdempotencyLookup::Cached(v) => assert_eq!(v.credit_limit, 42),
            IdempotencyLookup::Miss(_) => panic!("expected cached"),
        }
    }

    #[test]
    fn idempotency_rejects_request_id_reuse_with_different_payload() {
        let dir = TempDir::new().expect("tmp");
        let telemetry = Arc::new(Telemetry::new().expect("telemetry"));
        let svc = EvidenceOsService::build_with_options(
            dir.path().to_str().expect("utf8"),
            false,
            telemetry,
        )
        .expect("service");

        let req_a = pb::SetCreditLimitRequest {
            principal_id: "p1".to_string(),
            limit: 42,
        };
        let req_b = pb::SetCreditLimitRequest {
            principal_id: "p1".to_string(),
            limit: 43,
        };

        let lookup = svc
            .idempotency_lookup::<pb::SetCreditLimitRequest, pb::SetCreditLimitResponse>(
                "/evidenceos.v2.EvidenceOS/SetCreditLimit",
                "principal-a",
                "req-1",
                &req_a,
            )
            .expect("lookup");
        let ctx = match lookup {
            IdempotencyLookup::Miss(ctx) => ctx,
            IdempotencyLookup::Cached(_) => panic!("expected miss"),
        };
        svc.idempotency_store_success(ctx, &pb::SetCreditLimitResponse { credit_limit: 42 })
            .expect("store");

        let err = svc
            .idempotency_lookup::<pb::SetCreditLimitRequest, pb::SetCreditLimitResponse>(
                "/evidenceos.v2.EvidenceOS/SetCreditLimit",
                "principal-a",
                "req-1",
                &req_b,
            )
            .expect_err("must reject payload mismatch");
        assert_eq!(err.code(), Code::AlreadyExists);
    }
}
