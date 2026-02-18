// Copyright (c) 2026 Joseph Verdicchio and EvidenceOS Contributors
// SPDX-License-Identifier: Apache-2.0

//! ASPEC-like verifier for restricted WebAssembly modules.

use crate::error::{EvidenceOSError, EvidenceOSResult};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use wasmparser::{Operator, Parser, Payload, TypeRef};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum AspecLane {
    /// Strict verifier (default)
    HighAssurance,
    /// More permissive; intended for experimentation.
    LowAssurance,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AspecReport {
    pub lane: AspecLane,
    pub ok: bool,
    pub reasons: Vec<String>,
    pub imported_funcs: u32,
    pub defined_funcs: u32,
    pub instruction_count: u64,
    pub return_count: u64,
    pub estimated_capacity_bits: u64,
    pub data_segment_bytes: u64,
    pub data_entropy_ratio: f64,
    pub max_cyclomatic_complexity: u64,
    pub kolmogorov_proxy_bits: f64,
    pub heavy_lane_flag: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AspecPolicy {
    pub lane: AspecLane,
    /// Allowed imports as (module,name).
    pub allowed_imports: HashSet<(String, String)>,
    /// §A.1 P_data maximum data bytes.
    pub max_data_segment_bytes: u64,
    /// §A.1 P_entropy entropy ratio cap in [0,1].
    pub max_entropy_ratio: f64,
    /// §A.1 P_branch cyclomatic complexity cap.
    pub max_cyclomatic_complexity: u64,
    /// §A.1 P_io max output bytes proxy.
    pub max_output_bytes: u32,
    /// §A.1 six-sigma Kolmogorov proxy cap.
    pub kolmogorov_proxy_cap: u64,
}

impl Default for AspecPolicy {
    fn default() -> Self {
        let mut allowed = HashSet::new();
        allowed.insert(("env".to_string(), "oracle_query".to_string()));
        allowed.insert(("env".to_string(), "ledger_commit".to_string()));
        Self {
            lane: AspecLane::HighAssurance,
            allowed_imports: allowed,
            max_data_segment_bytes: 65_536,
            max_entropy_ratio: 0.75,
            max_cyclomatic_complexity: 50,
            max_output_bytes: 4096,
            kolmogorov_proxy_cap: 50_000,
        }
    }
}

fn normalized_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let n = data.len() as f64;
    let mut h = 0.0;
    for c in counts {
        if c > 0 {
            let p = c as f64 / n;
            h -= p * p.log2();
        }
    }
    (h / 8.0).clamp(0.0, 1.0)
}

fn has_compression_magic(data: &[u8]) -> bool {
    const MAGIC: [&[u8]; 5] = [
        &[0x1f, 0x8b],
        &[0x78, 0x9c],
        &[0x78, 0x01],
        &[0x04, 0x22, 0x4d, 0x18],
        &[0xfd, 0x2f, 0xb5, 0x28],
    ];
    MAGIC.iter().any(|m| data.windows(m.len()).any(|w| w == *m))
}

/// Verify a Wasm module against ASPEC predicates (§A.1).
pub fn verify_aspec(wasm: &[u8], policy: &AspecPolicy) -> EvidenceOSResult<AspecReport> {
    let mut reasons: Vec<String> = Vec::new();
    let mut imported_funcs: u32 = 0;
    let mut defined_funcs: u32 = 0;
    let mut call_edges: HashMap<u32, Vec<u32>> = HashMap::new();
    let mut instruction_count: u64 = 0;
    let mut return_count: u64 = 0;
    let mut total_conditional_branches: u64 = 0;
    let mut max_cyclomatic_complexity: u64 = 1;
    let mut next_defined_func_index: u32 = 0;
    let mut data_segment_bytes: u64 = 0;
    let mut data_bytes: Vec<u8> = Vec::new();
    let mut has_output_export = false;
    let mut loop_bound_markers = 0u64;
    let mut loop_markers_raw = wasm
        .windows("loop_bound:".len())
        .filter(|w| *w == b"loop_bound:")
        .count() as u64;

    let parser = Parser::new(0);
    for payload in parser.parse_all(wasm) {
        let payload = payload.map_err(|_| EvidenceOSError::AspecRejected)?;
        match payload {
            Payload::ImportSection(s) => {
                for import in s {
                    let import = import.map_err(|_| EvidenceOSError::AspecRejected)?;
                    match import.ty {
                        TypeRef::Func(_) => {
                            imported_funcs += 1;
                            let key = (import.module.to_string(), import.name.to_string());
                            if !policy.allowed_imports.contains(&key) {
                                reasons.push(format!(
                                    "banned import: {}::{}",
                                    import.module, import.name
                                ));
                            }
                        }
                        TypeRef::Memory(_) => reasons.push(
                            "memory imports are banned (define memory in-module)".to_string(),
                        ),
                        TypeRef::Table(_) => reasons.push("table imports are banned".to_string()),
                        TypeRef::Global(_) => reasons.push("global imports are banned".to_string()),
                        TypeRef::Tag(_) => {
                            reasons.push("exception tag imports are banned".to_string())
                        }
                    }
                }
            }
            Payload::ExportSection(s) => {
                for export in s {
                    let export = export.map_err(|_| EvidenceOSError::AspecRejected)?;
                    if export.name.to_ascii_lowercase().contains("output")
                        || export.name.to_ascii_lowercase().contains("result")
                    {
                        has_output_export = true;
                    }
                }
            }
            Payload::DataSection(s) => {
                for segment in s {
                    let segment = segment.map_err(|_| EvidenceOSError::AspecRejected)?;
                    let bytes = segment.data;
                    data_segment_bytes = data_segment_bytes
                        .checked_add(bytes.len() as u64)
                        .ok_or(EvidenceOSError::AspecRejected)?;
                    data_bytes.extend_from_slice(bytes);
                }
            }
            Payload::CustomSection(reader) => {
                let text = String::from_utf8_lossy(reader.data());
                loop_bound_markers =
                    loop_bound_markers.saturating_add(text.matches("loop_bound:").count() as u64);
            }
            Payload::FunctionSection(s) => defined_funcs = s.count(),
            Payload::CodeSectionStart { .. } => next_defined_func_index = 0,
            Payload::CodeSectionEntry(body) => {
                let func_index = imported_funcs + next_defined_func_index;
                let caller = func_index;
                next_defined_func_index += 1;
                let mut conditional_branches = 0u64;
                let mut reader = body
                    .get_operators_reader()
                    .map_err(|_| EvidenceOSError::AspecRejected)?;
                while !reader.eof() {
                    let op = reader.read().map_err(|_| EvidenceOSError::AspecRejected)?;
                    instruction_count += 1;
                    match op {
                        // §A.1 P_loops.
                        Operator::Loop { .. } => match policy.lane {
                            AspecLane::HighAssurance => {
                                reasons.push("loops are banned in HighAssurance".to_string())
                            }
                            AspecLane::LowAssurance => {
                                if loop_bound_markers == 0 && loop_markers_raw == 0 {
                                    reasons.push(
                                        "LowAssurance loop missing loop_bound:<n> marker"
                                            .to_string(),
                                    );
                                } else if loop_bound_markers > 0 {
                                    loop_bound_markers -= 1;
                                } else {
                                    loop_markers_raw -= 1;
                                }
                            }
                        },
                        Operator::BrTable { .. } => reasons.push("br_table is banned".to_string()),
                        Operator::CallIndirect { .. } => {
                            reasons.push("call_indirect is banned".to_string())
                        }
                        Operator::ReturnCall { .. } | Operator::ReturnCallIndirect { .. } => {
                            reasons.push("tail calls are banned".to_string())
                        }
                        Operator::MemoryGrow { .. } => {
                            reasons.push("memory.grow is banned".to_string())
                        }
                        Operator::TableGrow { .. }
                        | Operator::TableFill { .. }
                        | Operator::TableCopy { .. }
                        | Operator::TableInit { .. }
                        | Operator::TableGet { .. }
                        | Operator::TableSet { .. }
                        | Operator::TableSize { .. } => {
                            reasons.push("table operations are banned".to_string())
                        }
                        Operator::If { .. } | Operator::Br { .. } | Operator::BrIf { .. } => {
                            conditional_branches += 1;
                            total_conditional_branches += 1;
                        }
                        Operator::F32Abs
                        | Operator::F32Neg
                        | Operator::F32Ceil
                        | Operator::F32Floor
                        | Operator::F32Trunc
                        | Operator::F32Nearest
                        | Operator::F32Sqrt
                        | Operator::F32Add
                        | Operator::F32Sub
                        | Operator::F32Mul
                        | Operator::F32Div
                        | Operator::F32Min
                        | Operator::F32Max
                        | Operator::F32Copysign
                        | Operator::F64Abs
                        | Operator::F64Neg
                        | Operator::F64Ceil
                        | Operator::F64Floor
                        | Operator::F64Trunc
                        | Operator::F64Nearest
                        | Operator::F64Sqrt
                        | Operator::F64Add
                        | Operator::F64Sub
                        | Operator::F64Mul
                        | Operator::F64Div
                        | Operator::F64Min
                        | Operator::F64Max
                        | Operator::F64Copysign
                        | Operator::F32Eq
                        | Operator::F32Ne
                        | Operator::F32Lt
                        | Operator::F32Gt
                        | Operator::F32Le
                        | Operator::F32Ge
                        | Operator::F64Eq
                        | Operator::F64Ne
                        | Operator::F64Lt
                        | Operator::F64Gt
                        | Operator::F64Le
                        | Operator::F64Ge
                        | Operator::F32ConvertI32S
                        | Operator::F32ConvertI32U
                        | Operator::F32ConvertI64S
                        | Operator::F32ConvertI64U
                        | Operator::F32DemoteF64
                        | Operator::F64ConvertI32S
                        | Operator::F64ConvertI32U
                        | Operator::F64ConvertI64S
                        | Operator::F64ConvertI64U
                        | Operator::F64PromoteF32
                        | Operator::I32TruncF32S
                        | Operator::I32TruncF32U
                        | Operator::I32TruncF64S
                        | Operator::I32TruncF64U
                        | Operator::I64TruncF32S
                        | Operator::I64TruncF32U
                        | Operator::I64TruncF64S
                        | Operator::I64TruncF64U
                        | Operator::F32ReinterpretI32
                        | Operator::F64ReinterpretI64
                        | Operator::I32ReinterpretF32
                        | Operator::I64ReinterpretF64
                        | Operator::F32Const { .. }
                        | Operator::F64Const { .. } => {
                            if matches!(policy.lane, AspecLane::HighAssurance) {
                                reasons.push(
                                    "floating point is banned in HighAssurance lane".to_string(),
                                );
                            }
                        }
                        Operator::Call { function_index } => {
                            if function_index >= imported_funcs {
                                call_edges.entry(caller).or_default().push(function_index);
                            }
                        }
                        Operator::Return => return_count += 1,
                        Operator::Throw { .. }
                        | Operator::Rethrow { .. }
                        | Operator::Try { .. }
                        | Operator::Catch { .. }
                        | Operator::CatchAll
                        | Operator::Delegate { .. } => {
                            reasons.push("exceptions are banned".to_string())
                        }
                        _ => {}
                    }
                }
                max_cyclomatic_complexity = max_cyclomatic_complexity.max(1 + conditional_branches);
            }
            Payload::End(_) => {}
            _ => {}
        }
    }

    // §A.1 P_data.
    if data_segment_bytes > policy.max_data_segment_bytes {
        reasons.push(format!(
            "data segment bytes {} exceeds cap {}",
            data_segment_bytes, policy.max_data_segment_bytes
        ));
    }

    // §A.1 P_entropy.
    let data_entropy_ratio = normalized_entropy(&data_bytes);
    if data_entropy_ratio > policy.max_entropy_ratio {
        reasons.push(format!(
            "data entropy ratio {:.4} exceeds cap {}",
            data_entropy_ratio, policy.max_entropy_ratio
        ));
    }
    if has_compression_magic(&data_bytes) {
        reasons.push("compression magic detected in data segment".to_string());
    }

    // §A.1 P_branch.
    if max_cyclomatic_complexity > policy.max_cyclomatic_complexity {
        reasons.push(format!(
            "cyclomatic complexity {} exceeds cap {}",
            max_cyclomatic_complexity, policy.max_cyclomatic_complexity
        ));
    }

    // §A.1 P_io conservative proxy: Wasm cannot statically encode concrete return byte sizes,
    // so we bound total instruction count as 10x configured output byte budget.
    if has_output_export && instruction_count > u64::from(policy.max_output_bytes) * 10 {
        reasons.push(format!(
            "output proxy bound exceeded: instruction_count {} > {}",
            instruction_count,
            u64::from(policy.max_output_bytes) * 10
        ));
    }

    // Recursion/cycle check via iterative Kahn topological sort.
    let start = imported_funcs;
    let end = imported_funcs + defined_funcs;
    let mut indegree: HashMap<u32, u32> = (start..end).map(|f| (f, 0u32)).collect();
    for (&src, dsts) in &call_edges {
        if src < start || src >= end {
            continue;
        }
        for &dst in dsts {
            if let Some(v) = indegree.get_mut(&dst) {
                *v += 1;
            }
        }
    }
    let mut q: VecDeque<u32> = indegree
        .iter()
        .filter_map(|(n, d)| if *d == 0 { Some(*n) } else { None })
        .collect();
    let mut reached = HashSet::new();
    while let Some(n) = q.pop_front() {
        reached.insert(n);
        if let Some(neigh) = call_edges.get(&n) {
            for &m in neigh {
                if let Some(d) = indegree.get_mut(&m) {
                    *d -= 1;
                    if *d == 0 {
                        q.push_back(m);
                    }
                }
            }
        }
    }
    for n in start..end {
        if !reached.contains(&n) {
            reasons.push(format!("recursion/cycle detected involving func index {n}"));
        }
    }

    let data_entropy_bits = data_segment_bytes as f64 * data_entropy_ratio * 8.0;
    let branch_density_bits = total_conditional_branches as f64;
    let function_dispatch_bits = defined_funcs as f64 * 2.0;
    let kolmogorov_proxy_bits = data_entropy_bits + branch_density_bits + function_dispatch_bits;
    let heavy_lane_flag = kolmogorov_proxy_bits > policy.kolmogorov_proxy_cap as f64;
    if matches!(policy.lane, AspecLane::HighAssurance)
        && kolmogorov_proxy_bits > 1.5 * policy.kolmogorov_proxy_cap as f64
    {
        reasons.push(format!(
            "capacity bits {:.2} exceed HighAssurance cap {}",
            kolmogorov_proxy_bits,
            1.5 * policy.kolmogorov_proxy_cap as f64
        ));
    }

    let report = AspecReport {
        lane: policy.lane,
        ok: reasons.is_empty(),
        reasons,
        imported_funcs,
        defined_funcs,
        instruction_count,
        return_count,
        estimated_capacity_bits: kolmogorov_proxy_bits.round() as u64,
        data_segment_bytes,
        data_entropy_ratio,
        max_cyclomatic_complexity,
        kolmogorov_proxy_bits,
        heavy_lane_flag,
    };

    if report.ok {
        Ok(report)
    } else {
        Err(EvidenceOSError::AspecRejected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err_is_reject(result: EvidenceOSResult<AspecReport>) {
        assert!(matches!(result, Err(EvidenceOSError::AspecRejected)));
    }

    #[test]
    fn rejects_loop_highassurance() {
        let wasm = wat::parse_str("(module (func (loop nop)))").expect("valid wat");
        err_is_reject(verify_aspec(&wasm, &AspecPolicy::default()));
    }

    #[test]
    fn accepts_loop_lowassurance_with_bound() {
        let wasm = wat::parse_str("(module (@custom \"meta\" \"loop_bound:3\") (func (loop nop)))")
            .expect("valid wat");
        let mut policy = AspecPolicy {
            lane: AspecLane::LowAssurance,
            ..AspecPolicy::default()
        };
        policy.kolmogorov_proxy_cap = 1;
        let report = verify_aspec(&wasm, &policy).expect("should pass");
        assert!(report.ok);
    }

    #[test]
    fn rejects_data_segment_too_large() {
        let bytes = "a".repeat(70000);
        let wat = format!("(module (memory 2) (data (i32.const 0) \"{}\"))", bytes);
        let wasm = wat::parse_str(&wat).expect("valid wat");
        err_is_reject(verify_aspec(&wasm, &AspecPolicy::default()));
    }

    #[test]
    fn rejects_recursion() {
        let wasm = wat::parse_str("(module (func $a call 1) (func $b call 0))").expect("valid wat");
        err_is_reject(verify_aspec(&wasm, &AspecPolicy::default()));
    }

    #[test]
    fn capacity_bits_smoke() {
        let wasm = wat::parse_str("(module (func (if (i32.const 1) (then nop))) (memory 1) (data (i32.const 0) \"abcdef\"))")
            .expect("valid wat");
        let report = verify_aspec(
            &wasm,
            &AspecPolicy {
                lane: AspecLane::LowAssurance,
                ..AspecPolicy::default()
            },
        )
        .expect("should pass");
        assert!(report.kolmogorov_proxy_bits > 0.0);
    }
}
