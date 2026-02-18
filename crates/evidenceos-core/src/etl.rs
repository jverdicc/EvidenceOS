// Copyright (c) 2026 Joseph Verdicchio and EvidenceOS Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::error::{EvidenceOSError, EvidenceOSResult};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

pub type Hash32 = [u8; 32];

fn sha256(bytes: &[u8]) -> Hash32 {
    let mut h = Sha256::new();
    h.update(bytes);
    let out = h.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

/// CT-style domain-separated leaf hash: SHA256(0x00 || data)
pub fn leaf_hash(data: &[u8]) -> Hash32 {
    let mut buf = Vec::with_capacity(1 + data.len());
    buf.push(0u8);
    buf.extend_from_slice(data);
    sha256(&buf)
}

/// CT-style node hash: SHA256(0x01 || left || right)
pub fn node_hash(left: &Hash32, right: &Hash32) -> Hash32 {
    let mut buf = [0u8; 1 + 32 + 32];
    buf[0] = 1u8;
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
    let bounded = tree_size.min(leaves.len());
    merkle_root(&leaves[..bounded])
}

pub fn inclusion_proof(leaves: &[Hash32], leaf_index: usize) -> EvidenceOSResult<Vec<Hash32>> {
    if leaf_index >= leaves.len() {
        return Err(EvidenceOSError::NotFound);
    }
    let mut layer: Vec<Hash32> = leaves.to_vec();
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

#[derive(Debug)]
pub struct Etl {
    path: PathBuf,
    file: File,
    leaves: Vec<Hash32>,
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
        {
            let mut reader = BufReader::new(
                OpenOptions::new()
                    .read(true)
                    .open(&path)
                    .map_err(|_| EvidenceOSError::Internal)?,
            );
            loop {
                let mut len_bytes = [0u8; 4];
                match reader.read_exact(&mut len_bytes) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                    Err(_) => return Err(EvidenceOSError::Internal),
                }
                let len = u32::from_le_bytes(len_bytes) as usize;
                let mut data = vec![0u8; len];
                reader
                    .read_exact(&mut data)
                    .map_err(|_| EvidenceOSError::Internal)?;
                leaves.push(leaf_hash(&data));
            }
        }

        Ok(Self { path, file, leaves })
    }

    pub fn append(&mut self, data: &[u8]) -> EvidenceOSResult<(u64, Hash32)> {
        let len: u32 = data
            .len()
            .try_into()
            .map_err(|_| EvidenceOSError::InvalidArgument)?;
        self.file
            .write_all(&len.to_le_bytes())
            .map_err(|_| EvidenceOSError::Internal)?;
        self.file
            .write_all(data)
            .map_err(|_| EvidenceOSError::Internal)?;
        self.file.flush().map_err(|_| EvidenceOSError::Internal)?;

        let h = leaf_hash(data);
        let idx = self.leaves.len() as u64;
        self.leaves.push(h);
        Ok((idx, h))
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
        let mut f = OpenOptions::new()
            .read(true)
            .open(&self.path)
            .map_err(|_| EvidenceOSError::Internal)?;
        f.seek(SeekFrom::Start(0))
            .map_err(|_| EvidenceOSError::Internal)?;
        let mut i = 0u64;
        loop {
            let mut len_bytes = [0u8; 4];
            match f.read_exact(&mut len_bytes) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    return Err(EvidenceOSError::NotFound)
                }
                Err(_) => return Err(EvidenceOSError::Internal),
            }
            let len = u32::from_le_bytes(len_bytes) as usize;
            let mut data = vec![0u8; len];
            f.read_exact(&mut data)
                .map_err(|_| EvidenceOSError::Internal)?;
            if i == index {
                return Ok(data);
            }
            i += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merkle_root_is_stable() {
        let a = leaf_hash(b"a");
        let b = leaf_hash(b"b");
        let r1 = merkle_root(&[a, b]);
        let r2 = merkle_root(&[a, b]);
        assert_eq!(r1, r2);
    }

    #[test]
    fn etl_append_and_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("etl.log");
        {
            let mut etl = Etl::open_or_create(&path).unwrap();
            assert_eq!(etl.tree_size(), 0);
            etl.append(b"one").unwrap();
            etl.append(b"two").unwrap();
            assert_eq!(etl.tree_size(), 2);
        }
        {
            let etl = Etl::open_or_create(&path).unwrap();
            assert_eq!(etl.tree_size(), 2);
            let e0 = etl.read_entry(0).unwrap();
            assert_eq!(e0, b"one");
            let proof = etl.inclusion_proof(1).unwrap();
            assert!(!proof.is_empty());
        }
    }
}
