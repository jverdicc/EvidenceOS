use crate::error::{EvidenceOSError, EvidenceOSResult};
use crate::nullspec::NullSpecContractV1;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ActiveMappings {
    mappings: Vec<ActiveMapping>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ActiveMapping {
    oracle_id: String,
    holdout_handle: String,
    nullspec_id_hex: String,
}

pub struct NullSpecStore {
    dir: PathBuf,
    active_map_file: PathBuf,
}

impl NullSpecStore {
    pub fn open(data_dir: &Path) -> EvidenceOSResult<Self> {
        let dir = data_dir.join("nullspec");
        fs::create_dir_all(&dir).map_err(|_| EvidenceOSError::Internal)?;
        let active_map_file = dir.join("active_map.json");
        if !active_map_file.exists() {
            let bytes = serde_json::to_vec(&ActiveMappings::default())
                .map_err(|_| EvidenceOSError::Internal)?;
            fs::write(&active_map_file, bytes).map_err(|_| EvidenceOSError::Internal)?;
        }
        Ok(Self {
            dir,
            active_map_file,
        })
    }

    pub fn install(&self, contract: &NullSpecContractV1) -> EvidenceOSResult<()> {
        let id = hex::encode(contract.nullspec_id);
        let path = self.dir.join(format!("{id}.json"));
        fs::write(path, contract.canonical_bytes()).map_err(|_| EvidenceOSError::Internal)
    }

    pub fn get(&self, id: &[u8; 32]) -> EvidenceOSResult<NullSpecContractV1> {
        let path = self.dir.join(format!("{}.json", hex::encode(id)));
        let bytes = fs::read(path).map_err(|_| EvidenceOSError::NotFound)?;
        serde_json::from_slice(&bytes).map_err(|_| EvidenceOSError::Internal)
    }

    pub fn list(&self) -> EvidenceOSResult<Vec<NullSpecContractV1>> {
        let mut out = Vec::new();
        let entries = fs::read_dir(&self.dir).map_err(|_| EvidenceOSError::Internal)?;
        for entry in entries {
            let entry = entry.map_err(|_| EvidenceOSError::Internal)?;
            let path = entry.path();
            if path.file_name().and_then(|n| n.to_str()) == Some("active_map.json") {
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let bytes = fs::read(path).map_err(|_| EvidenceOSError::Internal)?;
            let c: NullSpecContractV1 =
                serde_json::from_slice(&bytes).map_err(|_| EvidenceOSError::Internal)?;
            out.push(c);
        }
        out.sort_by(|a, b| a.nullspec_id.cmp(&b.nullspec_id));
        Ok(out)
    }

    pub fn active_for(
        &self,
        oracle_id: &str,
        holdout_handle: &str,
    ) -> EvidenceOSResult<Option<[u8; 32]>> {
        let mappings = self.read_mappings()?;
        let found = mappings
            .mappings
            .iter()
            .find(|m| m.oracle_id == oracle_id && m.holdout_handle == holdout_handle);
        if let Some(m) = found {
            let decoded = hex::decode(&m.nullspec_id_hex).map_err(|_| EvidenceOSError::Internal)?;
            let arr: [u8; 32] = decoded.try_into().map_err(|_| EvidenceOSError::Internal)?;
            Ok(Some(arr))
        } else {
            Ok(None)
        }
    }

    pub fn rotate_active(
        &self,
        oracle_id: &str,
        holdout_handle: &str,
        nullspec_id: [u8; 32],
    ) -> EvidenceOSResult<()> {
        let mut mappings = self.read_mappings()?;
        let id_hex = hex::encode(nullspec_id);
        if let Some(m) = mappings
            .mappings
            .iter_mut()
            .find(|m| m.oracle_id == oracle_id && m.holdout_handle == holdout_handle)
        {
            m.nullspec_id_hex = id_hex;
        } else {
            mappings.mappings.push(ActiveMapping {
                oracle_id: oracle_id.to_string(),
                holdout_handle: holdout_handle.to_string(),
                nullspec_id_hex: id_hex,
            });
        }
        mappings.mappings.sort_by(|a, b| {
            a.oracle_id
                .cmp(&b.oracle_id)
                .then_with(|| a.holdout_handle.cmp(&b.holdout_handle))
        });
        self.write_mappings(&mappings)
    }

    fn read_mappings(&self) -> EvidenceOSResult<ActiveMappings> {
        let bytes = fs::read(&self.active_map_file).map_err(|_| EvidenceOSError::Internal)?;
        serde_json::from_slice(&bytes).map_err(|_| EvidenceOSError::Internal)
    }

    fn write_mappings(&self, mappings: &ActiveMappings) -> EvidenceOSResult<()> {
        let bytes = serde_json::to_vec(mappings).map_err(|_| EvidenceOSError::Internal)?;
        fs::write(&self.active_map_file, bytes).map_err(|_| EvidenceOSError::Internal)
    }
}
