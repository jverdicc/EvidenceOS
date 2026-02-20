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

const TOPIC_DOMAIN: &[u8] = b"evidenceos/topicid/v2/multisignal";
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
    pub semantic_hash: [u8; 32],
    pub physhir_hash: [u8; 32],
    pub lineage_root_hash: [u8; 32],
    pub output_schema_id_hash: [u8; 32],
    pub holdout_handle_hash: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TopicIdComputation {
    pub topic_id: [u8; 32],
    pub escalate_to_heavy: bool,
    pub disagreement_score: u32,
    pub semantic_physhir_distance_bits: u32,
}

pub fn hash_signal(label: &[u8], input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(label);
    hasher.update(input);
    hasher.finalize().into()
}

fn hamming_distance_bits(a: &[u8; 32], b: &[u8; 32]) -> u32 {
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| (x ^ y).count_ones())
        .sum()
}

pub fn compute_topic_id(_metadata: &ClaimMetadataV2, signals: &TopicSignals) -> TopicIdComputation {
    let mut hasher = Sha256::new();
    hasher.update(TOPIC_DOMAIN);
    hasher.update(signals.semantic_hash);
    hasher.update(signals.physhir_hash);
    hasher.update(signals.lineage_root_hash);
    hasher.update(signals.output_schema_id_hash);
    hasher.update(signals.holdout_handle_hash);
    let digest = hasher.finalize();

    let mut topic_id = [0u8; 32];
    topic_id.copy_from_slice(&digest);

    let semantic_physhir_distance_bits =
        hamming_distance_bits(&signals.semantic_hash, &signals.physhir_hash);
    let semantic_lineage_distance_bits =
        hamming_distance_bits(&signals.semantic_hash, &signals.lineage_root_hash);
    let physhir_lineage_distance_bits =
        hamming_distance_bits(&signals.physhir_hash, &signals.lineage_root_hash);
    let disagreement_score = semantic_physhir_distance_bits
        .saturating_add(semantic_lineage_distance_bits)
        .saturating_add(physhir_lineage_distance_bits);

    let semantic_physhir_match = semantic_physhir_distance_bits == 0;
    let lineage_disagrees = signals.lineage_root_hash != signals.semantic_hash
        || signals.lineage_root_hash != signals.physhir_hash;
    let escalate_to_heavy = if semantic_physhir_match && lineage_disagrees {
        false
    } else {
        semantic_physhir_distance_bits >= ESCALATE_HAMMING_THRESHOLD_BITS
    };

    TopicIdComputation {
        topic_id,
        escalate_to_heavy,
        disagreement_score,
        semantic_physhir_distance_bits,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::structured_claims;
    use proptest::prelude::*;

    fn metadata() -> ClaimMetadataV2 {
        ClaimMetadataV2 {
            lane: "high_assurance".to_string(),
            alpha_micros: 50_000,
            epoch_config_ref: "epoch/default".to_string(),
            output_schema_id: "schema/v1".to_string(),
        }
    }

    fn signals(seed: u8) -> TopicSignals {
        TopicSignals {
            semantic_hash: [seed; 32],
            physhir_hash: [seed.wrapping_add(1); 32],
            lineage_root_hash: [seed.wrapping_add(2); 32],
            output_schema_id_hash: [seed.wrapping_add(3); 32],
            holdout_handle_hash: [seed.wrapping_add(4); 32],
        }
    }

    #[test]
    fn stable_topic_id() {
        let sig = signals(7);
        let a = compute_topic_id(&metadata(), &sig);
        let b = compute_topic_id(&metadata(), &sig);
        assert_eq!(a.topic_id, b.topic_id);
    }

    #[test]
    fn determinism_across_metadata_permutations() {
        let sig = signals(10);
        let base = compute_topic_id(&metadata(), &sig);
        let mut m = metadata();
        m.lane = "fast".to_string();
        m.alpha_micros = 1;
        m.epoch_config_ref = "epoch/other".to_string();
        m.output_schema_id = "cbrn/v1".to_string();
        let changed = compute_topic_id(&m, &sig);
        assert_eq!(base.topic_id, changed.topic_id);
    }

    #[test]
    fn escalation_threshold_boundaries() {
        let mut semantic = [0u8; 32];
        semantic[..12].fill(0xFF);
        let at_96 = TopicSignals {
            semantic_hash: semantic,
            physhir_hash: [0; 32],
            ..signals(1)
        };
        assert!(compute_topic_id(&metadata(), &at_96).escalate_to_heavy);

        let mut below = [0u8; 32];
        below[..11].fill(0xFF);
        below[11] = 0b1111_1110; // 95 bits
        let at_95 = TopicSignals {
            semantic_hash: below,
            physhir_hash: [0; 32],
            ..signals(2)
        };
        assert!(!compute_topic_id(&metadata(), &at_95).escalate_to_heavy);

        let mut above = [0u8; 32];
        above[..12].fill(0xFF);
        above[12] = 0b1000_0000; // 97 bits
        let at_97 = TopicSignals {
            semantic_hash: above,
            physhir_hash: [0; 32],
            ..signals(3)
        };
        assert!(compute_topic_id(&metadata(), &at_97).escalate_to_heavy);
    }

    #[test]
    fn lineage_disagreement_does_not_escalate_when_semantic_physhir_match() {
        let sig = TopicSignals {
            semantic_hash: [9; 32],
            physhir_hash: [9; 32],
            lineage_root_hash: [7; 32],
            output_schema_id_hash: [1; 32],
            holdout_handle_hash: [2; 32],
        };
        let out = compute_topic_id(&metadata(), &sig);
        assert!(!out.escalate_to_heavy);
    }

    #[test]
    fn schema_alias_hash_consistency() {
        let canonical = structured_claims::canonicalize_schema_id("cbrn-sc.v1").expect("canonical");
        let alias = structured_claims::canonicalize_schema_id("schema/v1").expect("alias");
        let a = hash_signal(b"evidenceos/schema_id", canonical.as_bytes());
        let b = hash_signal(b"evidenceos/schema_id", alias.as_bytes());
        assert_eq!(a, b);
    }

    proptest! {
        #[test]
        fn random_signals_stable_and_non_panicking(
            semantic in any::<[u8; 32]>(),
            physhir in any::<[u8; 32]>(),
            lineage in any::<[u8; 32]>(),
            schema in any::<[u8; 32]>(),
            holdout in any::<[u8; 32]>(),
        ) {
            let sig = TopicSignals {
                semantic_hash: semantic,
                physhir_hash: physhir,
                lineage_root_hash: lineage,
                output_schema_id_hash: schema,
                holdout_handle_hash: holdout,
            };
            let a = compute_topic_id(&metadata(), &sig);
            let b = compute_topic_id(&metadata(), &sig);
            prop_assert_eq!(a.topic_id, b.topic_id);
        }

        #[test]
        fn disagreement_score_monotonic_with_flips(flip_count in 0u8..=32u8) {
            let semantic = [0u8; 32];
            let mut physhir = [0u8; 32];
            for b in physhir.iter_mut().take(flip_count as usize) {
                *b = 0xFF;
            }
            let low = compute_topic_id(&metadata(), &TopicSignals {
                semantic_hash: semantic,
                physhir_hash: [0u8; 32],
                lineage_root_hash: [0u8; 32],
                output_schema_id_hash: [1u8; 32],
                holdout_handle_hash: [2u8; 32],
            });
            let high = compute_topic_id(&metadata(), &TopicSignals {
                semantic_hash: semantic,
                physhir_hash: physhir,
                lineage_root_hash: [0u8; 32],
                output_schema_id_hash: [1u8; 32],
                holdout_handle_hash: [2u8; 32],
            });
            prop_assert!(high.disagreement_score >= low.disagreement_score);
        }
    }
}
