#![no_main]

use evidenceos_core::structured_claims;
use evidenceos_daemon::auth::decode_with_max_size;
use evidenceos_protocol::pb;
use libfuzzer_sys::fuzz_target;
use prost::Message;

const MAX_GRPC_FRAME: usize = 64 * 1024;

fn mutate_wire_bytes(seed: &[u8], data: &[u8]) -> Vec<u8> {
    let mut out = seed.to_vec();
    if out.is_empty() {
        out.extend_from_slice(data);
    }
    if out.is_empty() {
        out.push(0);
    }

    for (idx, b) in data.iter().enumerate() {
        let pos = idx % out.len();
        out[pos] ^= *b;
        if idx % 7 == 0 {
            out[pos] = out[pos].wrapping_add(*b);
        }
    }

    let keep = data.first().copied().unwrap_or_default() as usize;
    let limit = if out.is_empty() { 0 } else { keep % out.len() };
    out.truncate(limit.max(1));
    out
}

fuzz_target!(|data: &[u8]| {
    let decode_limit = data.len().min(MAX_GRPC_FRAME);

    let _ = decode_with_max_size::<pb::ExecuteClaimRequest>(data, decode_limit);

    let mut request = pb::ExecuteClaimRequest::decode(data).unwrap_or_default();
    if request.claim_id.is_empty() {
        request.claim_id = data.iter().copied().take(32).collect();
    }

    let mut encoded = Vec::new();
    if request.encode(&mut encoded).is_err() {
        return;
    }

    let mutated = mutate_wire_bytes(&encoded, data);
    if let Ok(decoded) = decode_with_max_size::<pb::ExecuteClaimRequest>(&mutated, MAX_GRPC_FRAME) {
        let _ = structured_claims::validate_and_canonicalize(
            structured_claims::SCHEMA_ID,
            &decoded.canonical_output,
        );
        let _ = structured_claims::validate_and_canonicalize(
            structured_claims::LEGACY_SCHEMA_ID,
            &decoded.canonical_output,
        );

        if let Ok(mut as_json) = serde_json::from_slice::<serde_json::Value>(&decoded.canonical_output)
        {
            if let Some(obj) = as_json.as_object_mut() {
                obj.insert(
                    "canonical_realization_map".to_string(),
                    serde_json::json!({
                        "decision": decoded.decision,
                        "reason_codes": decoded.reason_codes,
                    }),
                );
                let _ = serde_json::to_vec(&as_json);
            }
        }
    }
});
