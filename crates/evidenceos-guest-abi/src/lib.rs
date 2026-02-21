// Copyright (c) 2026 Joseph Verdicchio and EvidenceOS Contributors
// SPDX-License-Identifier: Apache-2.0

pub const ABI_VERSION: u32 = 1;
pub const ABI_FINGERPRINT: &str =
    "d0da6d7860987b893d7ce3e083b4977546a595074ef10f05d85b2ee7792cdffe";

pub const MODULE_ENV: &str = "env";
pub const MODULE_KERNEL_ALIAS: &str = "kernel";

pub const IMPORT_ORACLE_QUERY: &str = "oracle_query";
pub const IMPORT_ORACLE_BUCKET_ALIAS: &str = "oracle_bucket";
pub const IMPORT_EMIT_STRUCTURED_CLAIM: &str = "emit_structured_claim";
pub const IMPORT_DP_LAPLACE_I64: &str = "dp_laplace_i64";
pub const IMPORT_DP_GAUSSIAN_F64: &str = "dp_gaussian_f64";

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
const DP_LAPLACE_PARAMS: &[ValueType] = &[
    ValueType::I64,
    ValueType::F64,
    ValueType::F64,
    ValueType::F64,
];
const DP_GAUSSIAN_PARAMS: &[ValueType] = &[
    ValueType::F64,
    ValueType::F64,
    ValueType::F64,
    ValueType::F64,
];
const ORACLE_RESULTS: &[ValueType] = &[ValueType::I32];
const EMIT_RESULTS: &[ValueType] = &[ValueType::I32];
const DP_LAPLACE_RESULTS: &[ValueType] = &[ValueType::I64];
const DP_GAUSSIAN_RESULTS: &[ValueType] = &[ValueType::F64];

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

pub const OPTIONAL_IMPORTS: &[ImportSpec] = &[
    ImportSpec {
        module: MODULE_ENV,
        name: IMPORT_DP_LAPLACE_I64,
        params: DP_LAPLACE_PARAMS,
        results: DP_LAPLACE_RESULTS,
    },
    ImportSpec {
        module: MODULE_ENV,
        name: IMPORT_DP_GAUSSIAN_F64,
        params: DP_GAUSSIAN_PARAMS,
        results: DP_GAUSSIAN_RESULTS,
    },
];

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
    ImportSpec {
        module: MODULE_KERNEL_ALIAS,
        name: IMPORT_DP_LAPLACE_I64,
        params: DP_LAPLACE_PARAMS,
        results: DP_LAPLACE_RESULTS,
    },
    ImportSpec {
        module: MODULE_KERNEL_ALIAS,
        name: IMPORT_DP_GAUSSIAN_F64,
        params: DP_GAUSSIAN_PARAMS,
        results: DP_GAUSSIAN_RESULTS,
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
