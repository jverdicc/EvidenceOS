// Copyright (c) 2026 Joseph Verdicchio and EvidenceOS Contributors
// SPDX-License-Identifier: Apache-2.0

pub const ABI_VERSION: u32 = 2;
pub const ABI_FINGERPRINT: &str =
    "db8793ff74221f40caef0efedb443e703c066441a10bc07ec7628f4ccc5a0ff4";

pub const MODULE_ENV: &str = "env";
pub const MODULE_KERNEL_ALIAS: &str = "kernel";

pub const IMPORT_ORACLE_QUERY: &str = "oracle_query";
pub const IMPORT_ORACLE_BUCKET_ALIAS: &str = "oracle_bucket";
pub const IMPORT_EMIT_STRUCTURED_CLAIM: &str = "emit_structured_claim";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueType {
    I32,
    I64,
    F64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImportSpec {
    pub module: &'static str,
    pub name: &'static str,
    pub params: &'static [ValueType],
    pub results: &'static [ValueType],
}

const ORACLE_PARAMS: &[ValueType] = &[ValueType::I32, ValueType::I32];
const EMIT_PARAMS: &[ValueType] = &[ValueType::I32, ValueType::I32];
const ORACLE_RESULTS: &[ValueType] = &[ValueType::I32];
const EMIT_RESULTS: &[ValueType] = &[ValueType::I32];

pub const REQUIRED_IMPORTS: &[ImportSpec] = &[
    ImportSpec {
        module: MODULE_ENV,
        name: IMPORT_ORACLE_QUERY,
        params: ORACLE_PARAMS,
        results: ORACLE_RESULTS,
    },
    ImportSpec {
        module: MODULE_ENV,
        name: IMPORT_EMIT_STRUCTURED_CLAIM,
        params: EMIT_PARAMS,
        results: EMIT_RESULTS,
    },
];

pub const OPTIONAL_IMPORTS: &[ImportSpec] = &[];

pub const BACKCOMPAT_IMPORT_ALIASES: &[ImportSpec] = &[
    ImportSpec {
        module: MODULE_ENV,
        name: IMPORT_ORACLE_BUCKET_ALIAS,
        params: ORACLE_PARAMS,
        results: ORACLE_RESULTS,
    },
    ImportSpec {
        module: MODULE_KERNEL_ALIAS,
        name: IMPORT_ORACLE_QUERY,
        params: ORACLE_PARAMS,
        results: ORACLE_RESULTS,
    },
    ImportSpec {
        module: MODULE_KERNEL_ALIAS,
        name: IMPORT_ORACLE_BUCKET_ALIAS,
        params: ORACLE_PARAMS,
        results: ORACLE_RESULTS,
    },
    ImportSpec {
        module: MODULE_KERNEL_ALIAS,
        name: IMPORT_EMIT_STRUCTURED_CLAIM,
        params: EMIT_PARAMS,
        results: EMIT_RESULTS,
    },
];

pub fn all_imports() -> impl Iterator<Item = &'static ImportSpec> {
    REQUIRED_IMPORTS
        .iter()
        .chain(OPTIONAL_IMPORTS.iter())
        .chain(BACKCOMPAT_IMPORT_ALIASES.iter())
}

pub fn allowed_import_pairs() -> impl Iterator<Item = (&'static str, &'static str)> {
    all_imports().map(|spec| (spec.module, spec.name))
}

pub fn expected_import_signature(module: &str, name: &str) -> Option<&'static ImportSpec> {
    all_imports().find(|spec| spec.module == module && spec.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn abi_fingerprint_matches_manifest() {
        let mut manifest = String::new();
        manifest.push_str(&format!("v{ABI_VERSION}\n"));
        for spec in all_imports() {
            manifest.push_str(spec.module);
            manifest.push(':');
            manifest.push_str(spec.name);
            manifest.push(':');
            for p in spec.params {
                manifest.push_str(match p {
                    ValueType::I32 => "i32,",
                    ValueType::I64 => "i64,",
                    ValueType::F64 => "f64,",
                });
            }
            manifest.push_str("->");
            for r in spec.results {
                manifest.push_str(match r {
                    ValueType::I32 => "i32,",
                    ValueType::I64 => "i64,",
                    ValueType::F64 => "f64,",
                });
            }
            manifest.push('\n');
        }
        let digest = hex::encode(Sha256::digest(manifest.as_bytes()));
        assert_eq!(
            digest, ABI_FINGERPRINT,
            "guest ABI changed; perform explicit review and bump ABI_VERSION + ABI_FINGERPRINT"
        );
    }
}
