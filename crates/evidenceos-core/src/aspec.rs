//! ASPEC-like verifier for restricted WebAssembly modules.
//!
//! This is a *decidable* verifier intended for high-assurance lanes.
//!
//! The UVP paper describes ASPEC as a small admissibility language for
//! straight-line / DAG-like computations with bounded capacity.
//!
//! This reference implementation enforces a conservative subset:
//! - No `loop` blocks (syntactic loops)
//! - No indirect calls (`call_indirect`)
//! - No recursion (call graph must be acyclic)
//! - No floating point operators (require fixed-point / integer arithmetic)
//! - No `memory.grow`
//! - Imports restricted to an allowlist

use crate::error::{EvidenceOSError, EvidenceOSResult};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
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

    /// Conservative capacity estimate in bits.
    pub estimated_capacity_bits: u64,
}

#[derive(Debug, Clone)]
pub struct AspecPolicy {
    pub lane: AspecLane,

    /// Allowed imports as (module,name).
    pub allowed_imports: HashSet<(String, String)>,
}

impl Default for AspecPolicy {
    fn default() -> Self {
        let mut allowed = HashSet::new();
        allowed.insert(("env".to_string(), "oracle_query".to_string()));
        allowed.insert(("env".to_string(), "ledger_commit".to_string()));

        Self {
            lane: AspecLane::HighAssurance,
            allowed_imports: allowed,
        }
    }
}

pub fn verify_aspec(wasm: &[u8], policy: &AspecPolicy) -> EvidenceOSResult<AspecReport> {
    let mut reasons: Vec<String> = Vec::new();

    let mut imported_funcs: u32 = 0;
    let mut defined_funcs: u32 = 0;

    // For recursion check.
    let mut call_edges: HashMap<u32, Vec<u32>> = HashMap::new();

    let mut instruction_count: u64 = 0;
    let mut return_count: u64 = 0;

    // Track which function body we are currently parsing.
    let mut current_defined_func: Option<u32> = None;

    // wasmparser parses function bodies in order, but we need to map them to indices.
    // We'll compute this once we know the number of imported funcs.
    let mut next_defined_func_index: u32 = 0;

    let parser = Parser::new(0);
    for payload in parser.parse_all(wasm) {
        let payload = payload.map_err(|e| EvidenceOSError::AspecRejected(format!("parse error: {e}")))?;

        match payload {
            Payload::ImportSection(s) => {
                for import in s {
                    let import = import.map_err(|e| {
                        EvidenceOSError::AspecRejected(format!("import parse error: {e}"))
                    })?;

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
                        TypeRef::Memory(_) => {
                            reasons.push("memory imports are banned (define memory in-module)".to_string());
                        }
                        TypeRef::Table(_) => {
                            reasons.push("table imports are banned".to_string());
                        }
                        TypeRef::Global(_) => {
                            reasons.push("global imports are banned".to_string());
                        }
                        TypeRef::Tag(_) => {
                            reasons.push("exception tag imports are banned".to_string());
                        }
                    }
                }
            }
            Payload::FunctionSection(s) => {
                defined_funcs = s.count();
            }
            Payload::CodeSectionStart { .. } => {
                next_defined_func_index = 0;
            }
            Payload::CodeSectionEntry(body) => {
                let func_index = imported_funcs + next_defined_func_index;
                current_defined_func = Some(func_index);
                next_defined_func_index += 1;

                let mut reader = body.get_operators_reader().map_err(|e| {
                    EvidenceOSError::AspecRejected(format!("operators reader error: {e}"))
                })?;

                while !reader.eof() {
                    let op = reader.read().map_err(|e| {
                        EvidenceOSError::AspecRejected(format!("operator parse error: {e}"))
                    })?;
                    instruction_count += 1;

                    match op {
                        Operator::Loop { .. } => {
                            reasons.push("loops are banned (loop block)".to_string());
                        }
                        Operator::BrTable { .. } => {
                            reasons.push("br_table is banned".to_string());
                        }
                        Operator::CallIndirect { .. } => {
                            reasons.push("call_indirect is banned".to_string());
                        }
                        Operator::ReturnCall { .. } | Operator::ReturnCallIndirect { .. } => {
                            reasons.push("tail calls are banned".to_string());
                        }
                        Operator::MemoryGrow { .. } => {
                            reasons.push("memory.grow is banned".to_string());
                        }
                        Operator::TableGrow { .. }
                        | Operator::TableFill { .. }
                        | Operator::TableCopy { .. }
                        | Operator::TableInit { .. }
                        | Operator::TableGet { .. }
                        | Operator::TableSet { .. }
                        | Operator::TableSize { .. } => {
                            reasons.push("table operations are banned".to_string());
                        }

                        // floats: reject any float instruction in high assurance.
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
                                reasons.push("floating point is banned in HighAssurance lane".to_string());
                            }
                        }

                        Operator::Call { function_index } => {
                            if let Some(caller) = current_defined_func {
                                if function_index >= imported_funcs {
                                    call_edges.entry(caller).or_default().push(function_index);
                                }
                            }
                        }

                        Operator::Return => {
                            return_count += 1;
                        }

                        // Exception handling instructions are banned.
                        Operator::Throw { .. }
                        | Operator::Rethrow { .. }
                        | Operator::Try { .. }
                        | Operator::Catch { .. }
                        | Operator::CatchAll
                        | Operator::Delegate { .. } => {
                            reasons.push("exceptions are banned".to_string());
                        }

                        _ => {}
                    }
                }

                current_defined_func = None;
            }
            Payload::End(_) => {}
            _ => {}
        }
    }

    // Recursion check: call graph must be acyclic.
    let mut visiting: HashSet<u32> = HashSet::new();
    let mut visited: HashSet<u32> = HashSet::new();

    fn dfs(
        node: u32,
        edges: &HashMap<u32, Vec<u32>>,
        visiting: &mut HashSet<u32>,
        visited: &mut HashSet<u32>,
        reasons: &mut Vec<String>,
    ) {
        if visited.contains(&node) {
            return;
        }
        if !visiting.insert(node) {
            reasons.push(format!("recursion/cycle detected involving func index {node}"));
            return;
        }
        if let Some(neigh) = edges.get(&node) {
            for &m in neigh {
                dfs(m, edges, visiting, visited, reasons);
            }
        }
        visiting.remove(&node);
        visited.insert(node);
    }

    for f in imported_funcs..(imported_funcs + defined_funcs) {
        dfs(f, &call_edges, &mut visiting, &mut visited, &mut reasons);
    }

    let estimated_capacity_bits = return_count;
    let ok = reasons.is_empty();

    let report = AspecReport {
        lane: policy.lane,
        ok,
        reasons: reasons.clone(),
        imported_funcs,
        defined_funcs,
        instruction_count,
        return_count,
        estimated_capacity_bits,
    };

    if ok {
        Ok(report)
    } else {
        Err(EvidenceOSError::AspecRejected(format!(
            "{} violation(s): {}",
            reasons.len(),
            reasons.join("; ")
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_loop() {
        let wat = r#"(module
            (func (export \"run\")
                (loop
                    nop
                )
            )
        )"#;
        let wasm = wat::parse_str(wat).unwrap();
        let err = verify_aspec(&wasm, &AspecPolicy::default()).unwrap_err();
        match err {
            EvidenceOSError::AspecRejected(msg) => assert!(msg.contains("loops are banned")),
            _ => panic!("unexpected error"),
        }
    }

    #[test]
    fn accepts_straightline() {
        let wat = r#"(module
            (func (export \"run\") (result i32)
                i32.const 7
                return
            )
        )"#;
        let wasm = wat::parse_str(wat).unwrap();
        let report = verify_aspec(&wasm, &AspecPolicy::default()).unwrap();
        assert!(report.ok);
    }
}
