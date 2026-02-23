use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tonic::Status;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountLimits {
    pub credit_limit: u64,
    pub daily_mint_limit: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountRecord {
    pub credit_balance: u64,
    pub daily_mint_remaining: u64,
    pub last_mint_day: u64,
    pub limits: AccountLimits,
    pub burned_total: u64,
    pub denied_total: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct AccountsFile {
    accounts: HashMap<String, AccountRecord>,
}

#[derive(Debug, Clone, Copy)]
pub struct AccessCreditPricing {
    pub lambda_k_per_bit: u64,
    pub lambda_cpu_per_fuel: u64,
    pub lambda_mem_per_wasm_page: u64,
    pub worst_case_k_bits: u64,
    pub worst_case_fuel: u64,
    pub worst_case_wasm_pages: u64,
}

impl AccessCreditPricing {
    pub fn from_env() -> Self {
        Self {
            lambda_k_per_bit: read_env_u64("EVIDENCEOS_LAMBDA_K_PER_BIT", 1),
            lambda_cpu_per_fuel: read_env_u64("EVIDENCEOS_LAMBDA_CPU_PER_FUEL", 1),
            lambda_mem_per_wasm_page: read_env_u64("EVIDENCEOS_LAMBDA_MEM_PER_WASM_PAGE", 1_000),
            worst_case_k_bits: read_env_u64("EVIDENCEOS_CREDIT_WORST_CASE_K_BITS", 1_000_000),
            worst_case_fuel: read_env_u64("EVIDENCEOS_CREDIT_WORST_CASE_FUEL", 1_000_000),
            worst_case_wasm_pages: read_env_u64("EVIDENCEOS_CREDIT_WORST_CASE_PAGES", 16),
        }
    }

    pub fn charge(
        &self,
        k_bits: Option<u64>,
        fuel: Option<u64>,
        max_memory_pages: Option<u64>,
    ) -> u64 {
        let kb = k_bits.unwrap_or(self.worst_case_k_bits);
        let cpu = fuel.unwrap_or(self.worst_case_fuel);
        let mem = max_memory_pages.unwrap_or(self.worst_case_wasm_pages);
        self.lambda_k_per_bit
            .saturating_mul(kb)
            .saturating_add(self.lambda_cpu_per_fuel.saturating_mul(cpu))
            .saturating_add(self.lambda_mem_per_wasm_page.saturating_mul(mem))
    }
}

fn read_env_u64(key: &str, default_value: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .unwrap_or(default_value)
}

pub trait AdmissionProvider: Send + Sync {
    fn max_credit(&self, principal_id: &str) -> u64;
    fn admit(&self, principal_id: &str, requested: u64) -> Result<(), Status>;
}

#[derive(Debug, Clone)]
pub struct StaticAdmissionProvider {
    per_principal: HashMap<String, u64>,
    default_limit: u64,
}

impl StaticAdmissionProvider {
    pub fn from_env() -> Self {
        let default_limit = read_env_u64("EVIDENCEOS_DEFAULT_CREDIT_LIMIT", 10_000_000);
        let mut per_principal = HashMap::new();
        if let Ok(raw) = std::env::var("EVIDENCEOS_PRINCIPAL_CREDIT_LIMITS") {
            for pair in raw.split(',') {
                let mut fields = pair.splitn(2, '=');
                let principal = fields.next().unwrap_or_default().trim();
                let limit = fields.next().unwrap_or_default().trim();
                if principal.is_empty() {
                    continue;
                }
                if let Ok(parsed) = limit.parse::<u64>() {
                    per_principal.insert(principal.to_string(), parsed);
                }
            }
        }
        Self {
            per_principal,
            default_limit,
        }
    }
}

impl AdmissionProvider for StaticAdmissionProvider {
    fn max_credit(&self, principal_id: &str) -> u64 {
        self.per_principal
            .get(principal_id)
            .copied()
            .unwrap_or(self.default_limit)
    }

    fn admit(&self, principal_id: &str, requested: u64) -> Result<(), Status> {
        if requested > self.max_credit(principal_id) {
            return Err(Status::resource_exhausted(
                "requested credit exceeds admission limit",
            ));
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct AccountStore {
    path: PathBuf,
    accounts: HashMap<String, AccountRecord>,
}

impl AccountStore {
    pub fn open(root: &Path, default_limit: u64) -> Result<Self, Status> {
        let path = root.join("accounts.json");
        let accounts = if path.exists() {
            let bytes =
                std::fs::read(&path).map_err(|_| Status::internal("read accounts failed"))?;
            serde_json::from_slice::<AccountsFile>(&bytes)
                .map_err(|_| Status::internal("decode accounts failed"))?
                .accounts
        } else {
            HashMap::new()
        };
        let mut out = Self { path, accounts };
        let _ = out.ensure_account("anonymous", default_limit)?;
        Ok(out)
    }

    pub fn ensure_account(
        &mut self,
        principal_id: &str,
        default_limit: u64,
    ) -> Result<&mut AccountRecord, Status> {
        let now_day = unix_day_now()?;
        let record = self
            .accounts
            .entry(principal_id.to_string())
            .or_insert_with(|| AccountRecord {
                credit_balance: default_limit,
                daily_mint_remaining: default_limit,
                last_mint_day: now_day,
                limits: AccountLimits {
                    credit_limit: default_limit,
                    daily_mint_limit: default_limit,
                },
                burned_total: 0,
                denied_total: 0,
            });
        if record.last_mint_day != now_day {
            record.last_mint_day = now_day;
            record.daily_mint_remaining = record.limits.daily_mint_limit;
        }
        Ok(record)
    }

    pub fn burn(
        &mut self,
        principal_id: &str,
        amount: u64,
        default_limit: u64,
    ) -> Result<u64, Status> {
        let record = self.ensure_account(principal_id, default_limit)?;
        if record.credit_balance < amount {
            record.denied_total = record.denied_total.saturating_add(1);
            return Err(Status::resource_exhausted("insufficient credit"));
        }
        record.credit_balance = record.credit_balance.saturating_sub(amount);
        record.burned_total = record.burned_total.saturating_add(amount);
        self.persist()?;
        Ok(record.credit_balance)
    }

    pub fn grant_credit(
        &mut self,
        principal_id: &str,
        amount: u64,
        default_limit: u64,
    ) -> Result<u64, Status> {
        let record = self.ensure_account(principal_id, default_limit)?;
        record.credit_balance = record
            .credit_balance
            .saturating_add(amount)
            .min(record.limits.credit_limit);
        self.persist()?;
        Ok(record.credit_balance)
    }

    pub fn set_credit_limit(
        &mut self,
        principal_id: &str,
        limit: u64,
        default_limit: u64,
    ) -> Result<u64, Status> {
        let record = self.ensure_account(principal_id, default_limit)?;
        record.limits.credit_limit = limit;
        record.credit_balance = record.credit_balance.min(limit);
        self.persist()?;
        Ok(record.limits.credit_limit)
    }

    pub fn denied_total(&self, principal_id: &str) -> u64 {
        self.accounts
            .get(principal_id)
            .map(|r| r.denied_total)
            .unwrap_or(0)
    }

    pub fn burned_total(&self, principal_id: &str) -> u64 {
        self.accounts
            .get(principal_id)
            .map(|r| r.burned_total)
            .unwrap_or(0)
    }

    fn persist(&self) -> Result<(), Status> {
        let payload = serde_json::to_vec_pretty(&AccountsFile {
            accounts: self.accounts.clone(),
        })
        .map_err(|_| Status::internal("encode accounts failed"))?;
        write_file_atomic_durable(&self.path, &payload, "write accounts failed")
    }
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), Status> {
    let dir = File::open(path).map_err(|_| Status::internal("open directory failed"))?;
    dir.sync_all()
        .map_err(|_| Status::internal("sync directory failed"))
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), Status> {
    Ok(())
}

fn write_file_atomic_durable(
    path: &Path,
    bytes: &[u8],
    write_err: &'static str,
) -> Result<(), Status> {
    let parent = path
        .parent()
        .ok_or_else(|| Status::internal("path parent missing"))?;
    let tmp = path.with_extension("tmp");
    let mut f = File::create(&tmp).map_err(|_| Status::internal(write_err))?;
    f.write_all(bytes)
        .map_err(|_| Status::internal(write_err))?;
    f.sync_all().map_err(|_| Status::internal(write_err))?;
    std::fs::rename(&tmp, path).map_err(|_| Status::internal(write_err))?;
    sync_directory(parent)?;
    Ok(())
}

fn unix_day_now() -> Result<u64, Status> {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Status::internal("system clock before unix epoch"))?
        .as_secs();
    Ok(secs / 86_400)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn pricing_uses_worst_case_when_measurements_missing() {
        let pricing = AccessCreditPricing {
            lambda_k_per_bit: 2,
            lambda_cpu_per_fuel: 3,
            lambda_mem_per_wasm_page: 5,
            worst_case_k_bits: 7,
            worst_case_fuel: 11,
            worst_case_wasm_pages: 13,
        };
        let charged = pricing.charge(None, Some(10), None);
        assert_eq!(charged, 2 * 7 + 3 * 10 + 5 * 13);
    }

    #[test]
    fn account_store_enforces_principal_balance() {
        let tmp = TempDir::new().expect("tmp");
        let mut store = AccountStore::open(tmp.path(), 100).expect("open");
        store.burn("alice", 40, 100).expect("burn");
        assert!(store.burn("alice", 61, 100).is_err());
        let remaining = store.grant_credit("alice", 10, 100).expect("grant");
        assert_eq!(remaining, 70);
    }

    #[test]
    fn persist_is_atomic_when_write_fails() {
        let tmp = TempDir::new().expect("tmp");
        let accounts_path = tmp.path().join("accounts.json");
        fs::write(
            &accounts_path,
            b"{\"accounts\":{\"alice\":{\"credit_balance\":1}}}",
        )
        .expect("seed");

        let mut store = AccountStore {
            path: accounts_path.clone(),
            accounts: HashMap::new(),
        };
        store.accounts.insert(
            "bob".to_string(),
            AccountRecord {
                credit_balance: 2,
                daily_mint_remaining: 2,
                last_mint_day: 0,
                limits: AccountLimits {
                    credit_limit: 2,
                    daily_mint_limit: 2,
                },
                burned_total: 0,
                denied_total: 0,
            },
        );

        fs::create_dir(accounts_path.with_extension("tmp")).expect("block temp file creation");

        let err = store.persist().expect_err("persist should fail");
        assert_eq!(err.code(), tonic::Code::Internal);
        assert_eq!(
            fs::read(&accounts_path).expect("original still present"),
            b"{\"accounts\":{\"alice\":{\"credit_balance\":1}}}".to_vec()
        );
    }

    #[test]
    fn persist_is_atomic_when_rename_fails() {
        let tmp = TempDir::new().expect("tmp");
        let accounts_path = tmp.path().join("accounts.json");
        fs::create_dir(&accounts_path).expect("destination is directory");

        let mut store = AccountStore {
            path: accounts_path.clone(),
            accounts: HashMap::new(),
        };
        store.accounts.insert(
            "bob".to_string(),
            AccountRecord {
                credit_balance: 2,
                daily_mint_remaining: 2,
                last_mint_day: 0,
                limits: AccountLimits {
                    credit_limit: 2,
                    daily_mint_limit: 2,
                },
                burned_total: 0,
                denied_total: 0,
            },
        );

        let err = store.persist().expect_err("persist should fail");
        assert_eq!(err.code(), tonic::Code::Internal);
        assert!(
            accounts_path.is_dir(),
            "destination directory remains intact"
        );
    }
}
