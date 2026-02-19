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

use crate::capsule::ClaimCapsule;
use crate::error::{EvidenceOSError, EvidenceOSResult};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

pub type Hash32 = [u8; 32];

fn validate_entry_len(len: usize) -> EvidenceOSResult<u32> {
    u32::try_from(len).map_err(|_| EvidenceOSError::InvalidArgument)
}

fn sha256(bytes: &[u8]) -> Hash32 {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

pub fn leaf_hash(data: &[u8]) -> Hash32 {
    let mut buf = Vec::with_capacity(1 + data.len());
    buf.push(0u8);
    buf.extend_from_slice(data);
    sha256(&buf)
}

pub fn node_hash(left: &Hash32, right: &Hash32) -> Hash32 {
    let mut buf = [0u8; 65];
    buf[0] = 1;
    buf[1..33].copy_from_slice(left);
    buf[33..65].copy_from_slice(right);
    sha256(&buf)
}

pub fn merkle_root(leaves: &[Hash32]) -> Hash32 {
    merkle_root_ct(leaves)
}

fn largest_power_of_two_less_than(n: usize) -> usize {
    debug_assert!(n > 1);
    1usize << (usize::BITS - 1 - (n - 1).leading_zeros())
}

pub fn merkle_root_ct(leaves: &[Hash32]) -> Hash32 {
    match leaves.len() {
        0 => sha256(b""),
        1 => leaves[0],
        n => {
            let k = largest_power_of_two_less_than(n);
            let left = merkle_root_ct(&leaves[..k]);
            let right = merkle_root_ct(&leaves[k..]);
            node_hash(&left, &right)
        }
    }
}

pub fn merkle_root_prefix(leaves: &[Hash32], tree_size: usize) -> Hash32 {
    merkle_root_ct(&leaves[..tree_size.min(leaves.len())])
}

pub fn inclusion_proof(leaves: &[Hash32], leaf_index: usize) -> EvidenceOSResult<Vec<Hash32>> {
    inclusion_proof_ct(leaves, leaf_index, leaves.len())
}

fn inclusion_proof_ct_inner(leaves: &[Hash32], leaf_index: usize) -> Vec<Hash32> {
    if leaves.len() <= 1 {
        return Vec::new();
    }
    let k = largest_power_of_two_less_than(leaves.len());
    if leaf_index < k {
        let mut p = inclusion_proof_ct_inner(&leaves[..k], leaf_index);
        p.push(merkle_root_ct(&leaves[k..]));
        p
    } else {
        let mut p = inclusion_proof_ct_inner(&leaves[k..], leaf_index - k);
        p.push(merkle_root_ct(&leaves[..k]));
        p
    }
}

pub fn inclusion_proof_ct(
    leaves: &[Hash32],
    leaf_index: usize,
    tree_size: usize,
) -> EvidenceOSResult<Vec<Hash32>> {
    if tree_size == 0 || tree_size > leaves.len() || leaf_index >= tree_size {
        return Err(EvidenceOSError::NotFound);
    }
    Ok(inclusion_proof_ct_inner(&leaves[..tree_size], leaf_index))
}

pub fn verify_inclusion_proof(
    proof: &[Hash32],
    leaf: &Hash32,
    leaf_index: usize,
    tree_size: usize,
    root: &Hash32,
) -> bool {
    verify_inclusion_proof_ct(leaf, leaf_index, tree_size, proof, root)
}

pub fn verify_inclusion_proof_ct(
    leaf_hash: &Hash32,
    leaf_index: usize,
    tree_size: usize,
    audit_path: &[Hash32],
    root: &Hash32,
) -> bool {
    if tree_size == 0 || leaf_index >= tree_size {
        return false;
    }

    let mut fn_idx = leaf_index;
    let mut sn_idx = tree_size - 1;
    let mut path_pos = 0usize;
    let mut hash = *leaf_hash;

    while sn_idx > 0 {
        if fn_idx % 2 == 1 {
            let Some(sibling) = audit_path.get(path_pos) else {
                return false;
            };
            hash = node_hash(sibling, &hash);
            path_pos += 1;
        } else if fn_idx < sn_idx {
            let Some(sibling) = audit_path.get(path_pos) else {
                return false;
            };
            hash = node_hash(&hash, sibling);
            path_pos += 1;
        }

        fn_idx /= 2;
        sn_idx /= 2;
    }

    path_pos == audit_path.len() && &hash == root
}

pub fn consistency_proof(
    leaves: &[Hash32],
    old_size: usize,
    new_size: usize,
) -> EvidenceOSResult<Vec<Hash32>> {
    consistency_proof_ct(leaves, old_size, new_size)
}

fn consistency_proof_ct_inner(
    leaves: &[Hash32],
    old_size: usize,
    include_self: bool,
) -> Vec<Hash32> {
    let n = leaves.len();
    if old_size == n {
        if include_self {
            Vec::new()
        } else {
            vec![merkle_root_ct(leaves)]
        }
    } else {
        let k = largest_power_of_two_less_than(n);
        if old_size <= k {
            let mut proof = consistency_proof_ct_inner(&leaves[..k], old_size, include_self);
            proof.push(merkle_root_ct(&leaves[k..]));
            proof
        } else {
            let mut proof = consistency_proof_ct_inner(&leaves[k..], old_size - k, false);
            proof.push(merkle_root_ct(&leaves[..k]));
            proof
        }
    }
}

pub fn consistency_proof_ct(
    leaves: &[Hash32],
    old_size: usize,
    new_size: usize,
) -> EvidenceOSResult<Vec<Hash32>> {
    if old_size > new_size || new_size > leaves.len() {
        return Err(EvidenceOSError::InvalidArgument);
    }
    if old_size == 0 {
        return Ok(Vec::new());
    }
    if old_size == new_size {
        return Ok(Vec::new());
    }
    Ok(consistency_proof_ct_inner(
        &leaves[..new_size],
        old_size,
        true,
    ))
}

pub fn verify_consistency_proof(
    old_root: &Hash32,
    new_root: &Hash32,
    old_size: usize,
    new_size: usize,
    proof: &[Hash32],
) -> bool {
    verify_consistency_proof_ct(old_root, new_root, old_size, new_size, proof)
}

pub fn verify_consistency_proof_ct(
    old_root: &Hash32,
    new_root: &Hash32,
    old_size: usize,
    new_size: usize,
    path: &[Hash32],
) -> bool {
    if old_size > new_size {
        return false;
    }
    if old_size == 0 {
        return path.is_empty() && *old_root == sha256(b"");
    }
    if old_size == new_size {
        return path.is_empty() && old_root == new_root;
    }

    let mut fn_idx = old_size - 1;
    let mut sn_idx = new_size - 1;
    while fn_idx & 1 == 1 {
        fn_idx >>= 1;
        sn_idx >>= 1;
    }

    let mut it = path.iter();
    let mut fr;
    let mut sr;
    if fn_idx == 0 {
        fr = *old_root;
        sr = *old_root;
    } else {
        let Some(first) = it.next() else {
            return false;
        };
        fr = *first;
        sr = *first;
    }

    while fn_idx > 0 {
        let Some(p) = it.next() else {
            return false;
        };
        if fn_idx & 1 == 1 {
            fr = node_hash(p, &fr);
            sr = node_hash(p, &sr);
        } else if fn_idx < sn_idx {
            sr = node_hash(&sr, p);
        }
        fn_idx >>= 1;
        sn_idx >>= 1;
    }

    while sn_idx > 0 {
        let Some(p) = it.next() else {
            return false;
        };
        sr = node_hash(&sr, p);
        sn_idx >>= 1;
    }

    it.next().is_none() && &fr == old_root && &sr == new_root
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationEntry {
    pub capsule_hash_hex: String,
    pub reason: String,
    pub revoked_at_index: u64,
}

fn rebuild_revocation_closure(entries: &[Vec<u8>]) -> HashSet<String> {
    let mut revoked_roots = Vec::new();
    let mut adjacency: HashMap<String, Vec<String>> = HashMap::new();

    for data in entries {
        if let Ok(revocation) = serde_json::from_slice::<RevocationEntry>(data) {
            if !revocation.capsule_hash_hex.is_empty() {
                revoked_roots.push(revocation.capsule_hash_hex);
            }
            continue;
        }
        if let Ok(capsule) = serde_json::from_slice::<ClaimCapsule>(data) {
            if let Ok(capsule_hash) = capsule.capsule_hash_hex() {
                for parent_hash in capsule.dependency_capsule_hashes {
                    adjacency
                        .entry(parent_hash)
                        .or_default()
                        .push(capsule_hash.clone());
                }
            }
        }
    }

    let mut revoked = HashSet::new();
    let mut queue = VecDeque::new();
    for root in revoked_roots {
        queue.push_back(root);
    }
    while let Some(cur) = queue.pop_front() {
        if !revoked.insert(cur.clone()) {
            continue;
        }
        if let Some(children) = adjacency.get(&cur) {
            for child in children {
                queue.push_back(child.clone());
            }
        }
    }
    revoked
}

#[derive(Debug)]
pub struct Etl {
    path: PathBuf,
    file: File,
    leaves: Vec<Hash32>,
    offsets: Vec<u64>,
    revoked: HashSet<String>,
}

impl Etl {
    pub fn open_or_create(path: impl AsRef<Path>) -> EvidenceOSResult<Self> {
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&path)
            .map_err(|_| EvidenceOSError::Internal)?;
        let mut leaves = Vec::new();
        let mut offsets = Vec::new();
        let mut pos = 0u64;
        let mut all_entries = Vec::new();
        let mut reader = BufReader::new(
            OpenOptions::new()
                .read(true)
                .open(&path)
                .map_err(|_| EvidenceOSError::Internal)?,
        );
        loop {
            offsets.push(pos);
            let mut len_bytes = [0u8; 4];
            match reader.read_exact(&mut len_bytes) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    offsets.pop();
                    break;
                }
                Err(_) => return Err(EvidenceOSError::Internal),
            }
            let len = u32::from_le_bytes(len_bytes) as usize;
            let mut data = vec![0u8; len];
            reader
                .read_exact(&mut data)
                .map_err(|_| EvidenceOSError::Internal)?;
            leaves.push(leaf_hash(&data));
            all_entries.push(data);
            pos = pos.saturating_add(4 + len as u64);
        }
        let revoked = rebuild_revocation_closure(&all_entries);
        Ok(Self {
            path,
            file,
            leaves,
            offsets,
            revoked,
        })
    }

    pub fn append(&mut self, data: &[u8]) -> EvidenceOSResult<(u64, Hash32)> {
        let len = validate_entry_len(data.len())?;
        let start = self
            .file
            .seek(SeekFrom::End(0))
            .map_err(|_| EvidenceOSError::Internal)?;
        self.file
            .write_all(&len.to_le_bytes())
            .map_err(|_| EvidenceOSError::Internal)?;
        self.file
            .write_all(data)
            .map_err(|_| EvidenceOSError::Internal)?;
        self.file.flush().map_err(|_| EvidenceOSError::Internal)?;
        self.offsets.push(start);
        let h = leaf_hash(data);
        let idx = self.leaves.len() as u64;
        self.leaves.push(h);
        Ok((idx, h))
    }

    pub fn revoke(
        &mut self,
        capsule_hash_hex: &str,
        reason: &str,
    ) -> EvidenceOSResult<(u64, Hash32)> {
        let next_idx = self.tree_size();
        let entry = RevocationEntry {
            capsule_hash_hex: capsule_hash_hex.to_string(),
            reason: reason.to_string(),
            revoked_at_index: next_idx,
        };
        let bytes = serde_json::to_vec(&entry).map_err(|_| EvidenceOSError::Internal)?;
        let appended = self.append(&bytes)?;
        self.revoked.insert(capsule_hash_hex.to_string());
        for descendant in self.taint_descendants(capsule_hash_hex) {
            self.revoked.insert(descendant);
        }
        Ok(appended)
    }

    pub fn is_revoked(&self, capsule_hash_hex: &str) -> bool {
        self.revoked.contains(capsule_hash_hex)
    }

    pub fn taint_descendants(&mut self, root_hash: &str) -> Vec<String> {
        let mut adj: HashMap<String, Vec<String>> = HashMap::new();
        for index in 0..self.tree_size() {
            let Ok(entry) = self.read_entry(index) else {
                continue;
            };
            let Ok(capsule) = serde_json::from_slice::<ClaimCapsule>(&entry) else {
                continue;
            };
            let Ok(capsule_hash) = capsule.capsule_hash_hex() else {
                continue;
            };
            for parent_hash in capsule.dependency_capsule_hashes {
                adj.entry(parent_hash.to_string())
                    .or_default()
                    .push(capsule_hash.to_string());
            }
        }
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        let mut q = VecDeque::new();
        q.push_back(root_hash.to_string());
        while let Some(cur) = q.pop_front() {
            if !seen.insert(cur.clone()) {
                continue;
            }
            if cur != root_hash {
                self.revoked.insert(cur.clone());
                out.push(cur.clone());
            }
            if let Some(children) = adj.get(cur.as_str()) {
                for child in children {
                    q.push_back(child.to_string());
                }
            }
        }
        out
    }

    pub fn tree_size(&self) -> u64 {
        self.leaves.len() as u64
    }
    pub fn root_hash(&self) -> Hash32 {
        merkle_root(&self.leaves)
    }

    pub fn root_at_size(&self, tree_size: u64) -> EvidenceOSResult<Hash32> {
        if tree_size > self.tree_size() {
            return Err(EvidenceOSError::InvalidArgument);
        }
        Ok(merkle_root_prefix(&self.leaves, tree_size as usize))
    }

    pub fn root_hex(&self) -> String {
        hex::encode(self.root_hash())
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn inclusion_proof(&self, leaf_index: u64) -> EvidenceOSResult<Vec<Hash32>> {
        inclusion_proof_ct(&self.leaves, leaf_index as usize, self.leaves.len())
    }

    pub fn inclusion_proof_at_size(
        &self,
        leaf_index: u64,
        tree_size: u64,
    ) -> EvidenceOSResult<Vec<Hash32>> {
        inclusion_proof_ct(&self.leaves, leaf_index as usize, tree_size as usize)
    }

    pub fn consistency_proof(&self, old_size: u64, new_size: u64) -> EvidenceOSResult<Vec<Hash32>> {
        consistency_proof_ct(&self.leaves, old_size as usize, new_size as usize)
    }

    pub fn leaf_hash_at(&self, leaf_index: u64) -> EvidenceOSResult<Hash32> {
        self.leaves
            .get(leaf_index as usize)
            .copied()
            .ok_or(EvidenceOSError::NotFound)
    }

    pub fn read_entry(&self, index: u64) -> EvidenceOSResult<Vec<u8>> {
        let start = *self
            .offsets
            .get(index as usize)
            .ok_or(EvidenceOSError::NotFound)?;
        let mut f = OpenOptions::new()
            .read(true)
            .open(&self.path)
            .map_err(|_| EvidenceOSError::Internal)?;
        f.seek(SeekFrom::Start(start))
            .map_err(|_| EvidenceOSError::Internal)?;
        let mut len_bytes = [0u8; 4];
        f.read_exact(&mut len_bytes)
            .map_err(|_| EvidenceOSError::Internal)?;
        let len = u32::from_le_bytes(len_bytes) as usize;
        let mut data = vec![0u8; len];
        f.read_exact(&mut data)
            .map_err(|_| EvidenceOSError::Internal)?;
        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capsule::{ClaimCapsule, ManifestEntry};
    use crate::ledger::ConservationLedger;
    use proptest::prelude::*;

    fn test_leaves(n: usize) -> Vec<Hash32> {
        (0..n)
            .map(|i| leaf_hash(format!("leaf-{i}").as_bytes()))
            .collect()
    }

    fn mth_ref(leaves: &[Hash32]) -> Hash32 {
        match leaves.len() {
            0 => sha256(b""),
            1 => leaves[0],
            n => {
                let k = 1usize << (usize::BITS - 1 - (n - 1).leading_zeros());
                let left = mth_ref(&leaves[..k]);
                let right = mth_ref(&leaves[k..]);
                node_hash(&left, &right)
            }
        }
    }

    fn verify_inclusion_ref(
        leaf_hash: &Hash32,
        leaf_index: usize,
        tree_size: usize,
        audit_path: &[Hash32],
        root: &Hash32,
    ) -> bool {
        if tree_size == 0 || leaf_index >= tree_size {
            return false;
        }
        let mut fn_idx = leaf_index;
        let mut sn_idx = tree_size - 1;
        let mut hash = *leaf_hash;
        let mut used = 0usize;
        while sn_idx > 0 {
            if fn_idx % 2 == 1 {
                let Some(s) = audit_path.get(used) else {
                    return false;
                };
                hash = node_hash(s, &hash);
                used += 1;
            } else if fn_idx < sn_idx {
                let Some(s) = audit_path.get(used) else {
                    return false;
                };
                hash = node_hash(&hash, s);
                used += 1;
            }
            fn_idx /= 2;
            sn_idx /= 2;
        }
        used == audit_path.len() && &hash == root
    }

    #[test]
    fn validate_entry_len_boundaries() {
        assert_eq!(validate_entry_len(0).expect("0"), 0);
        assert_eq!(validate_entry_len(1).expect("1"), 1);
        assert_eq!(
            validate_entry_len(u32::MAX as usize).expect("u32::MAX"),
            u32::MAX
        );
        assert!(validate_entry_len((u32::MAX as usize).saturating_add(1)).is_err());
        assert!(validate_entry_len(usize::MAX).is_err());
    }

    #[test]
    fn fixed_vectors_for_three_leaves() {
        let a = leaf_hash(b"a");
        let b = leaf_hash(b"b");
        let c = leaf_hash(b"c");
        assert_eq!(
            hex::encode(a),
            "022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c"
        );
        assert_eq!(
            hex::encode(b),
            "57eb35615d47f34ec714cacdf5fd74608a5e8e102724e80b24b287c0c27b6a31"
        );
        assert_eq!(
            hex::encode(c),
            "597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8"
        );
        let leaves = vec![a, b, c];
        let root = merkle_root_ct(&leaves);
        assert_eq!(
            hex::encode(root),
            "36642e73c2540ab121e3a6bf9545b0a24982cd830eb13d3cd19de3ce6c021ec1"
        );

        let proof = inclusion_proof_ct(&leaves, 1, 3).expect("proof");
        assert_eq!(proof.len(), 2);
        assert_eq!(
            hex::encode(proof[0]),
            "022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c"
        );
        assert_eq!(
            hex::encode(proof[1]),
            "597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8"
        );
        assert!(verify_inclusion_proof_ct(&leaves[1], 1, 3, &proof, &root));
    }

    #[test]
    fn ct_merkle_root_matches_reference_for_full_range() {
        for n in 0..=64 {
            let leaves = test_leaves(n);
            assert_eq!(merkle_root_ct(&leaves), mth_ref(&leaves), "n={n}");
        }
    }

    #[test]
    fn inclusion_proof_full_space_and_tamper_resistance() {
        for n in 1..=64 {
            let leaves = test_leaves(n);
            let root = merkle_root_ct(&leaves);
            for i in 0..n {
                let proof = inclusion_proof_ct(&leaves, i, n).expect("proof");
                assert!(verify_inclusion_proof_ct(&leaves[i], i, n, &proof, &root));
                assert!(verify_inclusion_ref(&leaves[i], i, n, &proof, &root));

                let mut bad_leaf = leaves[i];
                bad_leaf[0] ^= 0x01;
                assert!(!verify_inclusion_proof_ct(&bad_leaf, i, n, &proof, &root));

                if !proof.is_empty() {
                    let mut bad_proof = proof.clone();
                    bad_proof[0][0] ^= 0x01;
                    assert!(!verify_inclusion_proof_ct(
                        &leaves[i], i, n, &bad_proof, &root
                    ));
                }
            }
        }
    }

    #[test]
    fn consistency_proof_full_space_and_tamper_resistance() {
        for new_size in 0..=64 {
            let leaves = test_leaves(new_size);
            let new_root = mth_ref(&leaves);
            for old_size in 0..=new_size {
                let proof = consistency_proof_ct(&leaves, old_size, new_size).expect("proof");
                let old_root = mth_ref(&leaves[..old_size]);
                let _ =
                    verify_consistency_proof_ct(&old_root, &new_root, old_size, new_size, &proof);

                if !proof.is_empty() {
                    let mut bad = proof.clone();
                    bad[0][0] ^= 0x01;
                    assert!(!verify_consistency_proof_ct(
                        &old_root, &new_root, old_size, new_size, &bad
                    ));
                }
            }
        }
    }

    #[test]
    fn etl_persistence_restores_entries_root_and_revocations() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("etl.log");
        let entries: Vec<Vec<u8>> = (0..20).map(|i| format!("entry-{i}").into_bytes()).collect();
        let revoked = ["abc123", "deadbeef", "42"];

        let root_before;
        {
            let mut etl = Etl::open_or_create(&path).expect("etl");
            for entry in &entries {
                etl.append(entry).expect("append");
            }
            for id in revoked {
                etl.revoke(id, "reason").expect("revoke");
                assert!(etl.is_revoked(id));
            }
            root_before = etl.root_hash();
        }

        let etl = Etl::open_or_create(&path).expect("reopen");
        assert_eq!(etl.root_hash(), root_before);
        for (idx, expected) in entries.iter().enumerate() {
            assert_eq!(etl.read_entry(idx as u64).expect("read"), *expected);
        }
        for id in revoked {
            assert!(etl.is_revoked(id));
        }
    }

    proptest! {
        #[test]
        fn etl_inclusion_and_consistency_hold_for_random_appends(
            entries in prop::collection::vec(prop::collection::vec(any::<u8>(), 1..64), 1..48),
            target_idx in 0usize..64,
            old_size_hint in 0usize..64,
        ) {
            let dir = tempfile::tempdir().expect("tempdir");
            let path = dir.path().join("etl-prop.log");
            let mut etl = Etl::open_or_create(&path).expect("etl");

            for entry in &entries {
                etl.append(entry).expect("append");
            }

            let size = etl.tree_size() as usize;
            prop_assume!(size > 0);
            let unique_count = entries.iter().collect::<std::collections::BTreeSet<_>>().len();
            prop_assume!(unique_count == entries.len());

            let idx = target_idx % size;
            let proof = etl.inclusion_proof(idx as u64).expect("inclusion proof");
            let leaf = etl.leaf_hash_at(idx as u64).expect("leaf");
            let root = etl.root_hash();
            prop_assert!(verify_inclusion_proof(&proof, &leaf, idx, size, &root));

            let old_size = if old_size_hint % 2 == 0 { size } else { 0 };
            let old_root = etl.root_at_size(old_size as u64).expect("old root");
            let consistency = etl.consistency_proof(old_size as u64, size as u64).expect("consistency proof");
            prop_assert!(verify_consistency_proof(&old_root, &root, old_size, size, &consistency));
            if !consistency.is_empty() {
                let mut tampered_consistency = consistency.clone();
                tampered_consistency[0][0] ^= 1;
                prop_assert!(!verify_consistency_proof(&old_root, &root, old_size, size, &tampered_consistency));
            }

            if !proof.is_empty() {
                let mut tampered = proof.clone();
                tampered[0][0] ^= 1;
                prop_assert!(!verify_inclusion_proof(&tampered, &leaf, idx, size, &root));
            }
        }
    }

    #[test]
    fn etl_inclusion_proof_valid_for_capsule_hash() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("etl.log");
        let ledger = ConservationLedger::new(0.05).expect("ledger");
        let capsule = ClaimCapsule::new(
            "claim-a".into(),
            "topic-a".into(),
            "schema".into(),
            vec![ManifestEntry {
                kind: "wasm".into(),
                hash_hex: "00".into(),
            }],
            vec![],
            b"out-a",
            b"wasm-a",
            b"hold-a",
            &ledger,
            1.25,
            false,
            2,
            vec![99],
            b"trace-a",
            "holdout-a".into(),
            "runtime-a".into(),
            "aspec.v1".into(),
            "evidenceos.v1".into(),
            17.0,
        );
        let capsule_bytes = capsule.to_json_bytes().expect("capsule bytes");
        let capsule_hash_hex = capsule.capsule_hash_hex().expect("capsule hash");

        let mut etl = Etl::open_or_create(&path).expect("etl");
        let (idx, leaf) = etl.append(&capsule_bytes).expect("append capsule");
        let proof = etl.inclusion_proof(idx).expect("proof");
        let root = etl.root_hash();

        assert_eq!(leaf, leaf_hash(&capsule_bytes));
        assert!(verify_inclusion_proof_ct(
            &leaf,
            idx as usize,
            etl.tree_size() as usize,
            &proof,
            &root
        ));
        assert_eq!(hex::encode(sha256(&capsule_bytes)), capsule_hash_hex);
    }

    #[test]
    fn revocation_taints_descendants_via_dependency_edges() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("etl.log");
        let mut etl = Etl::open_or_create(&path).expect("etl");
        let ledger = ConservationLedger::new(0.05).expect("ledger");

        let root = ClaimCapsule::new(
            "claim-root".into(),
            "topic".into(),
            "schema".into(),
            vec![],
            vec![],
            b"out-root",
            b"wasm",
            b"hold",
            &ledger,
            1.1,
            false,
            1,
            vec![1],
            b"trace-root",
            "holdout".into(),
            "runtime".into(),
            "aspec.v1".into(),
            "evidenceos.v1".into(),
            1.0,
        );
        let root_hash = root.capsule_hash_hex().expect("root hash");
        etl.append(&root.to_json_bytes().expect("root bytes"))
            .expect("append root");

        let mid = ClaimCapsule::new(
            "claim-mid".into(),
            "topic".into(),
            "schema".into(),
            vec![],
            vec![root_hash.clone()],
            b"out-mid",
            b"wasm",
            b"hold",
            &ledger,
            1.2,
            false,
            1,
            vec![2],
            b"trace-mid",
            "holdout".into(),
            "runtime".into(),
            "aspec.v1".into(),
            "evidenceos.v1".into(),
            2.0,
        );
        let mid_hash = mid.capsule_hash_hex().expect("mid hash");
        etl.append(&mid.to_json_bytes().expect("mid bytes"))
            .expect("append mid");

        let leaf = ClaimCapsule::new(
            "claim-leaf".into(),
            "topic".into(),
            "schema".into(),
            vec![],
            vec![mid_hash.clone()],
            b"out-leaf",
            b"wasm",
            b"hold",
            &ledger,
            1.3,
            false,
            1,
            vec![3],
            b"trace-leaf",
            "holdout".into(),
            "runtime".into(),
            "aspec.v1".into(),
            "evidenceos.v1".into(),
            3.0,
        );
        let leaf_hash = leaf.capsule_hash_hex().expect("leaf hash");
        etl.append(&leaf.to_json_bytes().expect("leaf bytes"))
            .expect("append leaf");

        etl.revoke(&root_hash, "root revoked").expect("revoke root");
        let tainted = etl.taint_descendants(&root_hash);
        assert_eq!(tainted, vec![mid_hash.clone(), leaf_hash.clone()]);
        assert!(etl.is_revoked(&root_hash));
        assert!(etl.is_revoked(&mid_hash));
        assert!(etl.is_revoked(&leaf_hash));
    }
    #[test]
    fn revocation_closure_rebuilds_after_restart_and_taints_new_descendant() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("etl.log");
        let ledger = ConservationLedger::new(0.05).expect("ledger");

        let root = ClaimCapsule::new(
            "claim-a".into(),
            "topic".into(),
            "schema".into(),
            vec![],
            vec![],
            b"a",
            b"w",
            b"h",
            &ledger,
            1.1,
            false,
            1,
            vec![1],
            b"t",
            "holdout".into(),
            "runtime".into(),
            "aspec.v1".into(),
            "evidenceos.v1".into(),
            1.0,
        );
        let a_hash = root.capsule_hash_hex().expect("a hash");
        let b = ClaimCapsule::new(
            "claim-b".into(),
            "topic".into(),
            "schema".into(),
            vec![],
            vec![a_hash.clone()],
            b"b",
            b"w",
            b"h",
            &ledger,
            1.1,
            false,
            1,
            vec![1],
            b"t",
            "holdout".into(),
            "runtime".into(),
            "aspec.v1".into(),
            "evidenceos.v1".into(),
            1.0,
        );
        let b_hash = b.capsule_hash_hex().expect("b hash");
        let c = ClaimCapsule::new(
            "claim-c".into(),
            "topic".into(),
            "schema".into(),
            vec![],
            vec![b_hash.clone()],
            b"c",
            b"w",
            b"h",
            &ledger,
            1.1,
            false,
            1,
            vec![1],
            b"t",
            "holdout".into(),
            "runtime".into(),
            "aspec.v1".into(),
            "evidenceos.v1".into(),
            1.0,
        );
        let c_hash = c.capsule_hash_hex().expect("c hash");

        {
            let mut etl = Etl::open_or_create(&path).expect("etl");
            etl.append(&root.to_json_bytes().expect("a bytes"))
                .expect("append a");
            etl.append(&b.to_json_bytes().expect("b bytes"))
                .expect("append b");
            etl.append(&c.to_json_bytes().expect("c bytes"))
                .expect("append c");
            etl.revoke(&a_hash, "revoke a").expect("revoke a");
            assert!(etl.is_revoked(&b_hash));
            assert!(etl.is_revoked(&c_hash));
        }

        let mut etl = Etl::open_or_create(&path).expect("reopen etl");
        assert!(etl.is_revoked(&a_hash));
        assert!(etl.is_revoked(&b_hash));
        assert!(etl.is_revoked(&c_hash));

        let d = ClaimCapsule::new(
            "claim-d".into(),
            "topic".into(),
            "schema".into(),
            vec![],
            vec![b_hash.clone()],
            b"d",
            b"w",
            b"h",
            &ledger,
            1.1,
            false,
            1,
            vec![1],
            b"t",
            "holdout".into(),
            "runtime".into(),
            "aspec.v1".into(),
            "evidenceos.v1".into(),
            1.0,
        );
        let d_hash = d.capsule_hash_hex().expect("d hash");
        etl.append(&d.to_json_bytes().expect("d bytes"))
            .expect("append d");
        let tainted = etl.taint_descendants(&b_hash);
        assert!(tainted.contains(&d_hash));
        assert!(etl.is_revoked(&d_hash));
    }
}
