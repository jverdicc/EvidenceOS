// Copyright (c) 2026 Joseph Verdicchio and EvidenceOS Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::error::{EvidenceOSError, EvidenceOSResult};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

pub type Hash32 = [u8; 32];

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
    if leaves.is_empty() {
        return sha256(b"");
    }
    let mut layer: Vec<Hash32> = leaves.to_vec();
    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len().div_ceil(2));
        let mut i = 0;
        while i < layer.len() {
            if i + 1 < layer.len() {
                next.push(node_hash(&layer[i], &layer[i + 1]));
            } else {
                next.push(layer[i]);
            }
            i += 2;
        }
        layer = next;
    }
    layer[0]
}

pub fn merkle_root_prefix(leaves: &[Hash32], tree_size: usize) -> Hash32 {
    merkle_root(&leaves[..tree_size.min(leaves.len())])
}

pub fn inclusion_proof(leaves: &[Hash32], leaf_index: usize) -> EvidenceOSResult<Vec<Hash32>> {
    if leaf_index >= leaves.len() {
        return Err(EvidenceOSError::NotFound);
    }
    let mut layer = leaves.to_vec();
    let mut idx = leaf_index;
    let mut proof = Vec::new();
    while layer.len() > 1 {
        if idx.is_multiple_of(2) {
            if idx + 1 < layer.len() {
                proof.push(layer[idx + 1]);
            }
        } else {
            proof.push(layer[idx - 1]);
        }
        let mut next = Vec::with_capacity(layer.len().div_ceil(2));
        let mut i = 0;
        while i < layer.len() {
            if i + 1 < layer.len() {
                next.push(node_hash(&layer[i], &layer[i + 1]));
            } else {
                next.push(layer[i]);
            }
            i += 2;
        }
        layer = next;
        idx /= 2;
    }
    Ok(proof)
}

pub fn verify_inclusion_proof(
    proof: &[Hash32],
    leaf: &Hash32,
    leaf_index: usize,
    tree_size: usize,
    root: &Hash32,
) -> bool {
    if tree_size == 0 || leaf_index >= tree_size {
        return false;
    }
    if tree_size == 1 {
        return proof.is_empty() && leaf == root;
    }
    let mut idx = leaf_index;
    let mut cur = *leaf;
    for sib in proof {
        cur = if idx.is_multiple_of(2) {
            node_hash(&cur, sib)
        } else {
            node_hash(sib, &cur)
        };
        idx /= 2;
    }
    &cur == root
}

pub fn consistency_proof(
    leaves: &[Hash32],
    old_size: usize,
    new_size: usize,
) -> EvidenceOSResult<Vec<Hash32>> {
    if old_size >= new_size || new_size > leaves.len() {
        return Err(EvidenceOSError::InvalidArgument);
    }
    if old_size == 0 {
        return Ok(Vec::new());
    }
    Ok(vec![
        merkle_root_prefix(leaves, old_size),
        merkle_root_prefix(leaves, new_size),
    ])
}

pub fn verify_consistency_proof(
    old_root: &Hash32,
    new_root: &Hash32,
    old_size: usize,
    new_size: usize,
    proof: &[Hash32],
) -> bool {
    if old_size >= new_size {
        return false;
    }
    if proof.len() != 2 {
        return false;
    }
    &proof[0] == old_root && &proof[1] == new_root
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationEntry {
    pub claim_hash_hex: String,
    pub reason: String,
    pub revoked_at_index: u64,
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
            pos = pos.saturating_add(4 + len as u64);
        }
        Ok(Self {
            path,
            file,
            leaves,
            offsets,
            revoked: HashSet::new(),
        })
    }

    pub fn append(&mut self, data: &[u8]) -> EvidenceOSResult<(u64, Hash32)> {
        let len: u32 = data
            .len()
            .try_into()
            .map_err(|_| EvidenceOSError::InvalidArgument)?;
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
        claim_hash_hex: &str,
        reason: &str,
    ) -> EvidenceOSResult<(u64, Hash32)> {
        let next_idx = self.tree_size();
        let entry = RevocationEntry {
            claim_hash_hex: claim_hash_hex.to_string(),
            reason: reason.to_string(),
            revoked_at_index: next_idx,
        };
        let bytes = serde_json::to_vec(&entry).map_err(|_| EvidenceOSError::Internal)?;
        let appended = self.append(&bytes)?;
        self.revoked.insert(claim_hash_hex.to_string());
        Ok(appended)
    }

    pub fn is_revoked(&self, claim_hash_hex: &str) -> bool {
        self.revoked.contains(claim_hash_hex)
    }

    pub fn taint_descendants(
        &mut self,
        dependency_dag: &[(String, String)],
        root_hash: &str,
    ) -> Vec<String> {
        let mut adj: HashMap<&str, Vec<&str>> = HashMap::new();
        for (p, c) in dependency_dag {
            adj.entry(p).or_default().push(c);
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
                    q.push_back((*child).to_string());
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
        inclusion_proof(&self.leaves, leaf_index as usize)
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

    #[test]
    fn verify_inclusion_proof_two_leaves_left() {
        let leaves = vec![leaf_hash(b"a"), leaf_hash(b"b")];
        let proof = inclusion_proof(&leaves, 0).expect("proof");
        assert!(verify_inclusion_proof(
            &proof,
            &leaves[0],
            0,
            2,
            &merkle_root(&leaves)
        ));
    }

    #[test]
    fn revocation_marks_hash() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("etl.log");
        let mut etl = Etl::open_or_create(&path).expect("etl");
        etl.revoke("abc123", "bad").expect("revoke");
        assert!(etl.is_revoked("abc123"));
    }

    #[test]
    fn etl_offset_seek_correctness() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("etl.log");
        let mut etl = Etl::open_or_create(&path).expect("etl");
        for i in 0..100u64 {
            etl.append(format!("entry-{i}").as_bytes()).expect("append");
        }
        assert_eq!(etl.read_entry(50).expect("read"), b"entry-50");
    }
}
