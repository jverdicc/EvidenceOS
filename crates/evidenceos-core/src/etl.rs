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
        let mut next = Vec::with_capacity((layer.len() + 1) / 2);
        let mut i = 0;
        while i < layer.len() {
            if i + 1 < layer.len() {
                next.push(node_hash(&layer[i], &layer[i + 1]));
            } else {
                // odd: carry
                next.push(layer[i]);
            }
            i += 2;
        }
        layer = next;
    }
    layer[0]
}

/// Evidence Transparency Log (append-only file + in-memory Merkle root).
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
            .map_err(|e| EvidenceOSError::Internal(format!("open etl: {e}")))?;

        // Rebuild leaves.
        let mut leaves = Vec::new();
        {
            let mut reader = BufReader::new(
                OpenOptions::new()
                    .read(true)
                    .open(&path)
                    .map_err(|e| EvidenceOSError::Internal(format!("open etl for read: {e}")))?,
            );
            loop {
                let mut len_bytes = [0u8; 4];
                match reader.read_exact(&mut len_bytes) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                    Err(e) => {
                        return Err(EvidenceOSError::Internal(format!(
                            "read etl length: {e}"
                        )))
                    }
                }
                let len = u32::from_le_bytes(len_bytes) as usize;
                let mut data = vec![0u8; len];
                reader
                    .read_exact(&mut data)
                    .map_err(|e| EvidenceOSError::Internal(format!("read etl entry: {e}")))?;
                leaves.push(leaf_hash(&data));
            }
        }

        Ok(Self { path, file, leaves })
    }

    pub fn append(&mut self, data: &[u8]) -> EvidenceOSResult<(u64, Hash32)> {
        let len: u32 = data
            .len()
            .try_into()
            .map_err(|_| EvidenceOSError::InvalidArgument("entry too large".to_string()))?;
        self.file
            .write_all(&len.to_le_bytes())
            .map_err(|e| EvidenceOSError::Internal(format!("etl write len: {e}")))?;
        self.file
            .write_all(data)
            .map_err(|e| EvidenceOSError::Internal(format!("etl write data: {e}")))?;
        self.file
            .flush()
            .map_err(|e| EvidenceOSError::Internal(format!("etl flush: {e}")))?;

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

    pub fn root_hex(&self) -> String {
        hex::encode(self.root_hash())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn read_entry(&self, index: u64) -> EvidenceOSResult<Vec<u8>> {
        // O(n) scan.
        let mut f = OpenOptions::new()
            .read(true)
            .open(&self.path)
            .map_err(|e| EvidenceOSError::Internal(format!("etl open read: {e}")))?;
        f.seek(SeekFrom::Start(0))
            .map_err(|e| EvidenceOSError::Internal(format!("etl seek: {e}")))?;
        let mut i = 0u64;
        loop {
            let mut len_bytes = [0u8; 4];
            match f.read_exact(&mut len_bytes) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    return Err(EvidenceOSError::NotFound(format!(
                        "etl index {index}"
                    )))
                }
                Err(e) => {
                    return Err(EvidenceOSError::Internal(format!(
                        "etl read len: {e}"
                    )))
                }
            }
            let len = u32::from_le_bytes(len_bytes) as usize;
            let mut data = vec![0u8; len];
            f.read_exact(&mut data)
                .map_err(|e| EvidenceOSError::Internal(format!("etl read data: {e}")))?;
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
        }
    }
}
