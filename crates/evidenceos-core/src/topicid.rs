// Copyright [2026] [Joseph Verdicchio]
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Copyright (c) 2026 Joseph Verdicchio and EvidenceOS Contributors
// SPDX-License-Identifier: Apache-2.0

use sha2::{Digest, Sha256};

const TOPIC_DOMAIN: &[u8] = b"evidenceos/topicid/v1";
/// Escalate to heavy lane when semantic hash and phys/hir signature hash disagree by this many bits.
pub const ESCALATE_HAMMING_THRESHOLD_BITS: u32 = 96;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimMetadataV2 {
    pub lane: String,
    pub alpha_micros: u32,
    pub epoch_config_ref: String,
    pub output_schema_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopicSignals {
    pub semantic_hash: Option<[u8; 32]>,
    pub phys_hir_signature_hash: [u8; 32],
    pub dependency_merkle_root: Option<[u8; 32]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TopicIdComputation {
    pub topic_id: [u8; 32],
    pub escalate_to_heavy: bool,
}

fn encode_len_prefixed_utf8(out: &mut Vec<u8>, value: &str) {
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value.as_bytes());
}

fn encode_opt_hash(out: &mut Vec<u8>, hash: Option<[u8; 32]>) {
    match hash {
        Some(value) => {
            out.push(1);
            out.extend_from_slice(&value);
        }
        None => out.push(0),
    }
}

fn hamming_distance_bits(a: &[u8; 32], b: &[u8; 32]) -> u32 {
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| (x ^ y).count_ones())
        .sum()
}

pub fn compute_topic_id(metadata: &ClaimMetadataV2, signals: &TopicSignals) -> TopicIdComputation {
    let mut encoded = Vec::with_capacity(256);
    encode_len_prefixed_utf8(&mut encoded, &metadata.lane);
    encoded.extend_from_slice(&metadata.alpha_micros.to_be_bytes());
    encode_len_prefixed_utf8(&mut encoded, &metadata.epoch_config_ref);
    encode_len_prefixed_utf8(&mut encoded, &metadata.output_schema_id);
    encode_opt_hash(&mut encoded, signals.semantic_hash);
    encoded.extend_from_slice(&signals.phys_hir_signature_hash);
    encode_opt_hash(&mut encoded, signals.dependency_merkle_root);

    let mut hasher = Sha256::new();
    hasher.update(TOPIC_DOMAIN);
    hasher.update(encoded);
    let digest = hasher.finalize();

    let mut topic_id = [0u8; 32];
    topic_id.copy_from_slice(&digest);

    let escalate_to_heavy = signals
        .semantic_hash
        .map(|semantic| {
            hamming_distance_bits(&semantic, &signals.phys_hir_signature_hash)
                >= ESCALATE_HAMMING_THRESHOLD_BITS
        })
        .unwrap_or(false);

    TopicIdComputation {
        topic_id,
        escalate_to_heavy,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metadata() -> ClaimMetadataV2 {
        ClaimMetadataV2 {
            lane: "high_assurance".to_string(),
            alpha_micros: 50_000,
            epoch_config_ref: "epoch/default".to_string(),
            output_schema_id: "schema/v1".to_string(),
        }
    }

    #[test]
    fn stable_topic_id() {
        let signals = TopicSignals {
            semantic_hash: Some([7; 32]),
            phys_hir_signature_hash: [7; 32],
            dependency_merkle_root: None,
        };
        let a = compute_topic_id(&metadata(), &signals);
        let b = compute_topic_id(&metadata(), &signals);
        assert_eq!(a.topic_id, b.topic_id);
        assert!(!a.escalate_to_heavy);
    }

    #[test]
    fn claim_name_is_not_input() {
        let signals = TopicSignals {
            semantic_hash: Some([1; 32]),
            phys_hir_signature_hash: [2; 32],
            dependency_merkle_root: Some([3; 32]),
        };
        let m = metadata();
        let t1 = compute_topic_id(&m, &signals);
        let t2 = compute_topic_id(&m, &signals);
        assert_eq!(t1.topic_id, t2.topic_id);
    }

    #[test]
    fn escalation_threshold_works() {
        let mut semantic = [0u8; 32];
        semantic[..12].fill(0xFF); // 96 bits
        let signals = TopicSignals {
            semantic_hash: Some(semantic),
            phys_hir_signature_hash: [0; 32],
            dependency_merkle_root: None,
        };
        assert!(compute_topic_id(&metadata(), &signals).escalate_to_heavy);
    }
}
