// Copyright (c) 2026 Joseph Verdicchio and EvidenceOS Contributors
// SPDX-License-Identifier: Apache-2.0

//! ASPEC-like verifier for restricted WebAssembly modules.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use wasmparser::{Operator, Parser, Payload, TypeRef};

const REQUIRED_OUTPUT_IMPORTS: [(&str, &str); 2] = [
    ("env", "emit_structured_claim"),
    ("kernel", "emit_structured_claim"),
];
const ALLOWED_EXPORTS: [&str; 2] = ["run", "memory"];

#[derive(Debug, Clone)]
struct Cfg {
    edges: Vec<Vec<usize>>,
}

#[derive(Debug, Clone)]
struct FunctionSummary {
    conditional_branches: u64,
    total_loops: u64,
    cfg: Cfg,
}

#[derive(Debug, Clone, Copy)]
enum ControlKind {
    Block,
    Loop,
    If,
}

type ControlMetadata = (Vec<Option<usize>>, Vec<Option<usize>>, Vec<Option<usize>>);

#[derive(Debug, Clone, Copy)]
struct ControlFrame {
    kind: ControlKind,
    start: usize,
    else_index: Option<usize>,
    end_index: Option<usize>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum AspecLane {
    /// Strict verifier (default)
    HighAssurance,
    /// More permissive; intended for experimentation.
    LowAssurance,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum FloatPolicy {
    RejectAll,
    Allow,
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
    pub total_loops: u64,
    pub bounds_used: Vec<u64>,
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
    /// §A.1 P_loops loop bound cap.
    pub max_loop_bound: u64,
    /// §A.1 six-sigma Kolmogorov proxy cap.
    pub kolmogorov_proxy_cap: u64,
    /// Appendix A.3 float determinism policy.
    pub float_policy: FloatPolicy,
}

impl Default for AspecPolicy {
    fn default() -> Self {
        let mut allowed = HashSet::new();
        allowed.insert(("env".to_string(), "oracle_bucket".to_string()));
        allowed.insert(("kernel".to_string(), "oracle_bucket".to_string()));
        allowed.insert(("env".to_string(), "emit_structured_claim".to_string()));
        allowed.insert(("kernel".to_string(), "emit_structured_claim".to_string()));
        Self {
            lane: AspecLane::HighAssurance,
            allowed_imports: allowed,
            max_data_segment_bytes: 65_536,
            max_entropy_ratio: 0.75,
            max_cyclomatic_complexity: 50,
            max_output_bytes: 4096,
            max_loop_bound: 1_000,
            kolmogorov_proxy_cap: 50_000,
            float_policy: FloatPolicy::RejectAll,
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

fn parse_loop_bounds(payload: &[u8], out: &mut VecDeque<u64>) {
    let text = String::from_utf8_lossy(payload);
    for tok in text.split_whitespace() {
        if let Some(raw) = tok.strip_prefix("loop_bound:") {
            let digits: String = raw.chars().take_while(|c| c.is_ascii_digit()).collect();
            if let Ok(v) = digits.parse::<u64>() {
                out.push_back(v);
            }
        }
    }
}

fn is_forbidden_output_import(module: &str, name: &str) -> bool {
    let lowered = format!("{module}::{name}").to_ascii_lowercase();
    lowered.contains("fd_write")
        || lowered.contains("console")
        || lowered.contains("stdout")
        || lowered.contains("output")
            && !REQUIRED_OUTPUT_IMPORTS
                .iter()
                .any(|(m, n)| module == *m && name == *n)
}

fn compute_control_metadata(ops: &[Operator<'_>]) -> Result<ControlMetadata, String> {
    let mut matching_end = vec![None; ops.len()];
    let mut if_to_else = vec![None; ops.len()];
    let mut if_to_end = vec![None; ops.len()];
    let mut stack: Vec<ControlFrame> = Vec::new();

    for (idx, op) in ops.iter().enumerate() {
        match op {
            Operator::Block { .. } => stack.push(ControlFrame {
                kind: ControlKind::Block,
                start: idx,
                else_index: None,
                end_index: None,
            }),
            Operator::Loop { .. } => stack.push(ControlFrame {
                kind: ControlKind::Loop,
                start: idx,
                else_index: None,
                end_index: None,
            }),
            Operator::If { .. } => stack.push(ControlFrame {
                kind: ControlKind::If,
                start: idx,
                else_index: None,
                end_index: None,
            }),
            Operator::Else => {
                let frame = stack
                    .last_mut()
                    .ok_or_else(|| "else without control frame".to_string())?;
                if !matches!(frame.kind, ControlKind::If) {
                    return Err("else attached to non-if frame".to_string());
                }
                frame.else_index = Some(idx);
                if_to_else[frame.start] = Some(idx);
            }
            Operator::End => {
                if let Some(mut frame) = stack.pop() {
                    frame.end_index = Some(idx);
                    matching_end[frame.start] = Some(idx);
                    if matches!(frame.kind, ControlKind::If) {
                        if_to_end[frame.start] = Some(idx);
                    }
                }
            }
            _ => {}
        }
    }

    if !stack.is_empty() {
        return Err("unterminated control frame".to_string());
    }

    Ok((matching_end, if_to_else, if_to_end))
}

fn branch_target(control_stack: &[ControlFrame], depth: u32) -> Option<usize> {
    let len = control_stack.len();
    let idx = len.checked_sub(1 + depth as usize)?;
    let frame = control_stack.get(idx)?;
    match frame.kind {
        ControlKind::Loop => Some(frame.start),
        ControlKind::Block | ControlKind::If => frame.end_index,
    }
}

fn build_cfg(ops: &[Operator<'_>]) -> Result<Cfg, String> {
    let node_count = ops.len() + 1;
    let exit = ops.len();
    let mut edges = vec![Vec::<usize>::new(); node_count];
    let (matching_end, if_to_else, if_to_end) = compute_control_metadata(ops)?;
    let mut control_stack: Vec<ControlFrame> = Vec::new();

    for (idx, op) in ops.iter().enumerate() {
        let next = idx + 1;
        match op {
            Operator::Block { .. } => {
                control_stack.push(ControlFrame {
                    kind: ControlKind::Block,
                    start: idx,
                    else_index: None,
                    end_index: matching_end[idx],
                });
                edges[idx].push(next);
            }
            Operator::Loop { .. } => {
                control_stack.push(ControlFrame {
                    kind: ControlKind::Loop,
                    start: idx,
                    else_index: None,
                    end_index: matching_end[idx],
                });
                edges[idx].push(next);
            }
            Operator::If { .. } => {
                let else_idx = if_to_else[idx];
                let end_idx = if_to_end[idx];
                control_stack.push(ControlFrame {
                    kind: ControlKind::If,
                    start: idx,
                    else_index: else_idx,
                    end_index: end_idx,
                });
                edges[idx].push(next);
                edges[idx].push(else_idx.unwrap_or(end_idx.unwrap_or(next)) + 1);
            }
            Operator::Else => {
                let frame = control_stack
                    .last()
                    .ok_or_else(|| "else without frame in cfg builder".to_string())?;
                if !matches!(frame.kind, ControlKind::If) {
                    return Err("else on non-if frame in cfg builder".to_string());
                }
                edges[idx].push(frame.end_index.unwrap_or(exit) + 1);
            }
            Operator::End => {
                let _ = control_stack.pop();
                edges[idx].push(next);
            }
            Operator::Br { relative_depth } => {
                if let Some(target) = branch_target(&control_stack, *relative_depth) {
                    edges[idx].push(target);
                } else {
                    return Err("invalid br depth".to_string());
                }
            }
            Operator::BrIf { relative_depth } => {
                if let Some(target) = branch_target(&control_stack, *relative_depth) {
                    edges[idx].push(target);
                    edges[idx].push(next);
                } else {
                    return Err("invalid br_if depth".to_string());
                }
            }
            Operator::Return => edges[idx].push(exit),
            _ => edges[idx].push(next),
        }
    }

    Ok(Cfg { edges })
}

fn tarjans_scc(cfg: &Cfg) -> Vec<Vec<usize>> {
    struct Tarjan<'a> {
        cfg: &'a Cfg,
        index: usize,
        stack: Vec<usize>,
        on_stack: Vec<bool>,
        indices: Vec<Option<usize>>,
        lowlink: Vec<usize>,
        sccs: Vec<Vec<usize>>,
    }
    impl<'a> Tarjan<'a> {
        fn strongconnect(&mut self, v: usize) {
            self.indices[v] = Some(self.index);
            self.lowlink[v] = self.index;
            self.index += 1;
            self.stack.push(v);
            self.on_stack[v] = true;

            for &w in &self.cfg.edges[v] {
                if self.indices[w].is_none() {
                    self.strongconnect(w);
                    self.lowlink[v] = self.lowlink[v].min(self.lowlink[w]);
                } else if self.on_stack[w] {
                    if let Some(w_idx) = self.indices[w] {
                        self.lowlink[v] = self.lowlink[v].min(w_idx);
                    }
                }
            }

            if self.indices[v].is_some_and(|idx| self.lowlink[v] == idx) {
                let mut component = Vec::new();
                while let Some(w) = self.stack.pop() {
                    self.on_stack[w] = false;
                    component.push(w);
                    if w == v {
                        break;
                    }
                }
                self.sccs.push(component);
            }
        }
    }

    let n = cfg.edges.len();
    let mut tarjan = Tarjan {
        cfg,
        index: 0,
        stack: Vec::new(),
        on_stack: vec![false; n],
        indices: vec![None; n],
        lowlink: vec![0; n],
        sccs: Vec::new(),
    };
    for v in 0..n {
        if tarjan.indices[v].is_none() {
            tarjan.strongconnect(v);
        }
    }
    tarjan.sccs
}

fn is_reducible_cfg(cfg: &Cfg) -> bool {
    let sccs = tarjans_scc(cfg);
    for scc in sccs {
        let node_set: HashSet<usize> = scc.iter().copied().collect();
        let is_cycle = scc.len() > 1 || scc.first().is_some_and(|n| cfg.edges[*n].contains(n));
        if !is_cycle {
            continue;
        }
        let mut entries = HashSet::new();
        for &n in &scc {
            for (src, succs) in cfg.edges.iter().enumerate() {
                if !node_set.contains(&src) && succs.contains(&n) {
                    entries.insert(n);
                }
            }
        }
        if entries.len() > 1 {
            return false;
        }
    }
    true
}

fn analyze_function(ops: &[Operator<'_>]) -> Result<FunctionSummary, String> {
    let cfg = build_cfg(ops)?;
    let conditional_branches = ops
        .iter()
        .filter(|op| matches!(op, Operator::If { .. } | Operator::BrIf { .. }))
        .count() as u64;
    let total_loops = ops
        .iter()
        .filter(|op| matches!(op, Operator::Loop { .. }))
        .count() as u64;
    Ok(FunctionSummary {
        conditional_branches,
        total_loops,
        cfg,
    })
}

/// Verify a Wasm module against ASPEC predicates (§A.1).
pub fn verify_aspec(wasm: &[u8], policy: &AspecPolicy) -> AspecReport {
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
    let mut loop_bounds: VecDeque<u64> = VecDeque::new();
    let mut exported_names = Vec::new();
    let mut has_run_export = false;
    let mut has_output_import = false;
    let mut total_loops: u64 = 0;
    let mut bounds_used = Vec::new();

    let parser = Parser::new(0);
    for payload in parser.parse_all(wasm) {
        let payload = match payload {
            Ok(payload) => payload,
            Err(_) => {
                reasons.push("invalid wasm payload".to_string());
                continue;
            }
        };
        match payload {
            Payload::ImportSection(s) => {
                for import in s {
                    let import = match import {
                        Ok(import) => import,
                        Err(_) => {
                            reasons.push("invalid import section".to_string());
                            continue;
                        }
                    };
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
                            if REQUIRED_OUTPUT_IMPORTS
                                .iter()
                                .any(|(m, n)| import.module == *m && import.name == *n)
                            {
                                has_output_import = true;
                            }
                            if is_forbidden_output_import(import.module, import.name) {
                                reasons.push(format!(
                                    "forbidden output channel import: {}::{}",
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
                    let export = match export {
                        Ok(export) => export,
                        Err(_) => {
                            reasons.push("invalid export section".to_string());
                            continue;
                        }
                    };
                    let name = export.name.to_string();
                    exported_names.push(name.clone());
                    if name == "run" {
                        has_run_export = true;
                    }
                    if !ALLOWED_EXPORTS.contains(&name.as_str()) {
                        reasons.push(format!("disallowed export: {name}"));
                    }
                }
            }
            Payload::DataSection(s) => {
                for segment in s {
                    let segment = match segment {
                        Ok(segment) => segment,
                        Err(_) => {
                            reasons.push("invalid data segment".to_string());
                            continue;
                        }
                    };
                    let bytes = segment.data;
                    match data_segment_bytes.checked_add(bytes.len() as u64) {
                        Some(next) => data_segment_bytes = next,
                        None => {
                            data_segment_bytes = u64::MAX;
                            reasons.push("data segment length overflow".to_string());
                        }
                    }
                    data_bytes.extend_from_slice(bytes);
                }
            }
            Payload::CustomSection(reader) => {
                parse_loop_bounds(reader.data(), &mut loop_bounds);
            }
            Payload::FunctionSection(s) => defined_funcs = s.count(),
            Payload::CodeSectionStart { .. } => next_defined_func_index = 0,
            Payload::CodeSectionEntry(body) => {
                let func_index = imported_funcs + next_defined_func_index;
                let caller = func_index;
                next_defined_func_index += 1;
                let reader = body.get_operators_reader();
                let Ok(mut reader) = reader else {
                    reasons.push("invalid code section".to_string());
                    continue;
                };
                let mut ops = Vec::new();
                while !reader.eof() {
                    let op = match reader.read() {
                        Ok(op) => op,
                        Err(_) => {
                            reasons.push("invalid instruction stream".to_string());
                            break;
                        }
                    };
                    instruction_count += 1;
                    match op {
                        Operator::Loop { .. } => {
                            total_loops += 1;
                            match policy.lane {
                                AspecLane::HighAssurance => {
                                    reasons.push("loops are banned in HighAssurance".to_string())
                                }
                                AspecLane::LowAssurance => {
                                    if let Some(bound) = loop_bounds.pop_front() {
                                        if bound > policy.max_loop_bound {
                                            reasons.push(format!(
                                                "loop bound {} exceeds cap {}",
                                                bound, policy.max_loop_bound
                                            ));
                                        }
                                        bounds_used.push(bound);
                                    } else {
                                        reasons.push(
                                            "LowAssurance loop missing loop_bound:<n> marker"
                                                .to_string(),
                                        );
                                    }
                                }
                            }
                        }
                        Operator::BrTable { .. } => reasons
                            .push("br_table is banned and treated as irreducible".to_string()),
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
                            if matches!(policy.lane, AspecLane::HighAssurance)
                                && matches!(policy.float_policy, FloatPolicy::RejectAll)
                            {
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
                    ops.push(op);
                }

                match analyze_function(&ops) {
                    Ok(summary) => {
                        if !is_reducible_cfg(&summary.cfg) {
                            reasons.push(format!("irreducible CFG in function {func_index}"));
                        }
                        total_conditional_branches += summary.conditional_branches;
                        max_cyclomatic_complexity =
                            max_cyclomatic_complexity.max(1 + summary.conditional_branches);
                        if summary.total_loops > 0
                            && matches!(policy.lane, AspecLane::HighAssurance)
                        {
                            // reason already emitted above, keep deterministic loop counting path.
                        }
                    }
                    Err(err) => reasons.push(format!(
                        "failed to build CFG for function {func_index}: {err}"
                    )),
                }
            }
            Payload::End(_) => {}
            _ => {}
        }
    }

    if !has_run_export {
        reasons.push("missing required export: run".to_string());
    }
    if exported_names.is_empty() {
        reasons.push("module exports must include run".to_string());
    }

    if !has_output_import {
        reasons
            .push("missing required import emit_structured_claim in env:: or kernel::".to_string());
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

    // §A.1 P_io proxy: cap instruction budget by output size.
    if instruction_count > u64::from(policy.max_output_bytes) * 10 {
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

    AspecReport {
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
        total_loops,
        bounds_used,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_module(body: &str) -> Vec<u8> {
        let wat = format!(
            "(module
                (import \"kernel\" \"emit_structured_claim\" (func $emit (param i32 i32)))
                (func (export \"run\") {body})
             )"
        );
        wat::parse_str(&wat).unwrap()
    }

    fn low_policy() -> AspecPolicy {
        AspecPolicy {
            lane: AspecLane::LowAssurance,
            float_policy: FloatPolicy::Allow,
            ..AspecPolicy::default()
        }
    }

    fn encode_u32_leb(mut value: u32, out: &mut Vec<u8>) {
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if value == 0 {
                break;
            }
        }
    }

    fn decode_u32_leb(bytes: &[u8], at: &mut usize) -> Option<u32> {
        let mut value = 0u32;
        let mut shift = 0;
        while *at < bytes.len() && shift < 35 {
            let b = bytes[*at];
            *at += 1;
            value |= u32::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                return Some(value);
            }
            shift += 7;
        }
        None
    }

    fn insert_meta_before_code_section(wasm: &[u8], payload: &str) -> Vec<u8> {
        let mut out = Vec::with_capacity(wasm.len() + payload.len() + 32);
        out.extend_from_slice(&wasm[..8]);

        let mut i = 8usize;
        let mut inserted = false;
        while i < wasm.len() {
            let section_id = wasm[i];
            i += 1;
            let mut leb_at = i;
            let Some(size) = decode_u32_leb(wasm, &mut leb_at) else {
                return wasm.to_vec();
            };
            let header = &wasm[i..leb_at];
            i = leb_at;
            let end = i.saturating_add(size as usize);
            if end > wasm.len() {
                return wasm.to_vec();
            }

            if !inserted && section_id == 10 {
                let mut custom_payload = Vec::new();
                encode_u32_leb(4, &mut custom_payload);
                custom_payload.extend_from_slice(b"meta");
                custom_payload.extend_from_slice(payload.as_bytes());
                out.push(0);
                let mut sz = Vec::new();
                encode_u32_leb(custom_payload.len() as u32, &mut sz);
                out.extend_from_slice(&sz);
                out.extend_from_slice(&custom_payload);
                inserted = true;
            }

            out.push(section_id);
            out.extend_from_slice(header);
            out.extend_from_slice(&wasm[i..end]);
            i = end;
        }
        out
    }

    #[test]
    fn p_import_allowlist_pass_and_fail() {
        let ok = base_module("nop");
        assert!(verify_aspec(&ok, &AspecPolicy::default()).ok);

        let bad = wat::parse_str(
            "(module
                (import \"evil\" \"sink\" (func))
                (import \"kernel\" \"emit_structured_claim\" (func (param i32 i32)))
                (func (export \"run\") nop))",
        )
        .unwrap();
        assert!(!verify_aspec(&bad, &AspecPolicy::default()).ok);
    }

    #[test]
    fn p_opcode_forbidden_classes_reject() {
        let modules = [
            "(module (import \"kernel\" \"emit_structured_claim\" (func (param i32 i32))) (func (export \"run\") (call_indirect (type 0) (i32.const 0))) (type (func)))",
            "(module (import \"kernel\" \"emit_structured_claim\" (func (param i32 i32))) (func (export \"run\") (return_call 0)))",
            "(module (import \"kernel\" \"emit_structured_claim\" (func (param i32 i32))) (func (export \"run\") (table.grow (i32.const 0) (ref.null func))))",
        ];
        for wat in modules {
            let wasm = wat::parse_str(wat).unwrap();
            assert!(!verify_aspec(&wasm, &AspecPolicy::default()).ok);
        }
    }

    #[test]
    fn p_nogrow_memory_grow_reject() {
        let wasm = wat::parse_str(
            "(module
                (import \"kernel\" \"emit_structured_claim\" (func (param i32 i32)))
                (memory 1)
                (func (export \"run\") (drop (memory.grow (i32.const 1)))))",
        )
        .unwrap();
        assert!(!verify_aspec(&wasm, &AspecPolicy::default()).ok);
    }

    #[test]
    fn p_cfg_br_table_reject_as_irreducible() {
        let wasm = wat::parse_str(
            "(module
                (import \"kernel\" \"emit_structured_claim\" (func (param i32 i32)))
                (func (export \"run\")
                  (block
                    (br_table 0 (i32.const 0))
                  )
                ))",
        )
        .unwrap();
        assert!(!verify_aspec(&wasm, &AspecPolicy::default()).ok);
    }

    #[test]
    fn p_callgraph_self_and_mutual_recursion_reject() {
        let self_rec = wat::parse_str(
            "(module
                (import \"kernel\" \"emit_structured_claim\" (func (param i32 i32)))
                (func (export \"run\") call 1)
                (func call 1))",
        )
        .unwrap();
        assert!(!verify_aspec(&self_rec, &AspecPolicy::default()).ok);

        let mutual = wat::parse_str(
            "(module
                (import \"kernel\" \"emit_structured_claim\" (func (param i32 i32)))
                (func (export \"run\") call 2)
                (func call 3)
                (func call 2))",
        )
        .unwrap();
        assert!(!verify_aspec(&mutual, &AspecPolicy::default()).ok);
    }

    #[test]
    fn p_loops_high_assurance_reject() {
        let wasm = base_module("(loop nop)");
        assert!(!verify_aspec(&wasm, &AspecPolicy::default()).ok);
    }

    #[test]
    fn p_loops_low_assurance_bounds_enforced() {
        let mut policy = low_policy();
        policy.max_loop_bound = 1;

        let missing = base_module("(loop nop)");
        assert!(!verify_aspec(&missing, &policy).ok);

        let exact = insert_meta_before_code_section(&base_module("(loop nop)"), "loop_bound:1");
        assert!(verify_aspec(&exact, &policy).ok);

        let over = insert_meta_before_code_section(&base_module("(loop nop)"), "loop_bound:2");
        assert!(!verify_aspec(&over, &policy).ok);

        let two_loops = base_module("(loop nop) (loop nop)");
        let two_one_bound = insert_meta_before_code_section(&two_loops, "loop_bound:1");
        assert!(!verify_aspec(&two_one_bound, &policy).ok);

        let two_two_bounds =
            insert_meta_before_code_section(&two_loops, "loop_bound:1 loop_bound:0");
        assert!(verify_aspec(&two_two_bounds, &policy).ok);
    }

    #[test]
    fn p_data_boundaries() {
        let policy = AspecPolicy {
            max_data_segment_bytes: 1,
            ..AspecPolicy::default()
        };

        let exact = wat::parse_str(
            "(module
                (import \"kernel\" \"emit_structured_claim\" (func (param i32 i32)))
                (memory 1)
                (data (i32.const 0) \"a\")
                (func (export \"run\") nop))",
        )
        .unwrap();
        assert!(verify_aspec(&exact, &policy).ok);

        let over = wat::parse_str(
            "(module
                (import \"kernel\" \"emit_structured_claim\" (func (param i32 i32)))
                (memory 1)
                (data (i32.const 0) \"ab\")
                (func (export \"run\") nop))",
        )
        .unwrap();
        assert!(!verify_aspec(&over, &policy).ok);

        let zero_policy = AspecPolicy {
            max_data_segment_bytes: 0,
            ..AspecPolicy::default()
        };
        let none = base_module("nop");
        assert!(verify_aspec(&none, &zero_policy).ok);
    }

    #[test]
    fn p_entropy_low_accept_high_with_magic_reject() {
        let low = wat::parse_str(
            "(module
                (import \"kernel\" \"emit_structured_claim\" (func (param i32 i32)))
                (memory 1)
                (data (i32.const 0) \"aaaaaaaa\")
                (func (export \"run\") nop))",
        )
        .unwrap();
        assert!(verify_aspec(&low, &AspecPolicy::default()).ok);

        let mut bytes = vec![0x1f, 0x8b];
        bytes.extend(0u8..=255);
        let mut wat_data = String::new();
        for b in bytes {
            wat_data.push_str(&format!("\\{:02x}", b));
        }
        let high_wat = format!(
            "(module
                (import \"kernel\" \"emit_structured_claim\" (func (param i32 i32)))
                (memory 1)
                (data (i32.const 0) \"{wat_data}\")
                (func (export \"run\") nop))"
        );
        let high = wat::parse_str(&high_wat).unwrap();
        assert!(!verify_aspec(&high, &AspecPolicy::default()).ok);
    }

    #[test]
    fn p_branch_complexity_boundaries() {
        let policy = AspecPolicy {
            max_cyclomatic_complexity: 2,
            ..AspecPolicy::default()
        };

        let below = base_module("(if (i32.const 1) (then nop))");
        assert!(verify_aspec(&below, &policy).ok);

        let above = base_module("(if (i32.const 1) (then nop)) (br_if 0 (i32.const 1))");
        assert!(!verify_aspec(&above, &policy).ok);
    }

    #[test]
    fn p_io_exports_and_imports_enforced() {
        let missing_run = wat::parse_str(
            "(module
                (import \"kernel\" \"emit_structured_claim\" (func (param i32 i32)))
                (func (export \"not_run\") nop))",
        )
        .unwrap();
        assert!(!verify_aspec(&missing_run, &AspecPolicy::default()).ok);

        let extra_export = wat::parse_str(
            "(module
                (import \"kernel\" \"emit_structured_claim\" (func (param i32 i32)))
                (func (export \"run\") nop)
                (func (export \"debug\") nop))",
        )
        .unwrap();
        assert!(!verify_aspec(&extra_export, &AspecPolicy::default()).ok);

        let missing_emit_import = wat::parse_str("(module (func (export \"run\") nop))").unwrap();
        assert!(!verify_aspec(&missing_emit_import, &AspecPolicy::default()).ok);

        let good = base_module("nop");
        assert!(verify_aspec(&good, &AspecPolicy::default()).ok);
    }

    #[test]
    fn boundary_params_output_kolmogorov_and_heavy_flag() {
        let wasm = base_module("(if (i32.const 1) (then nop))");

        let output_policy = AspecPolicy {
            max_output_bytes: 0,
            ..AspecPolicy::default()
        };
        assert!(!verify_aspec(&wasm, &output_policy).ok);

        let output_policy_ok = AspecPolicy {
            max_output_bytes: 1,
            ..AspecPolicy::default()
        };
        assert!(verify_aspec(&wasm, &output_policy_ok).ok);

        let k_policy = AspecPolicy {
            kolmogorov_proxy_cap: 2,
            ..AspecPolicy::default()
        };
        let report = verify_aspec(&wasm, &k_policy);
        assert!(report.heavy_lane_flag);

        let k_policy_clear = AspecPolicy {
            kolmogorov_proxy_cap: 3,
            ..AspecPolicy::default()
        };
        let report = verify_aspec(&wasm, &k_policy_clear);
        assert!(!report.heavy_lane_flag);
    }
}

#[cfg(test)]
mod float_policy_tests {
    use super::*;

    #[test]
    fn high_assurance_rejects_float_when_policy_rejects() {
        let wasm = wat::parse_str(
            r#"(module
            (import "kernel" "emit_structured_claim" (func (param i32 i32)))
            (memory (export "memory") 1)
            (func (export "run")
                f32.const 1.0
                drop
            )
        )"#,
        )
        .expect("wat");
        let report = verify_aspec(&wasm, &AspecPolicy::default());
        assert!(!report.ok);
    }

    #[test]
    fn p_float_low_assurance_allows() {
        let wasm = wat::parse_str(
            r#"(module
            (import "kernel" "emit_structured_claim" (func $emit (param i32 i32)))
            (memory (export "memory") 1)
            (data (i32.const 0) "x")
            (func (export "run")
                f32.const 1.0
                drop
                i32.const 0
                i32.const 1
                call $emit
            )
        )"#,
        )
        .expect("wat");
        let mut policy = AspecPolicy {
            lane: AspecLane::LowAssurance,
            ..AspecPolicy::default()
        };
        policy.float_policy = FloatPolicy::Allow;
        let report = verify_aspec(&wasm, &policy);
        assert!(report.ok, "{:?}", report.reasons);
    }
}

#[cfg(test)]
mod prop_tests {
    use super::*;
    use proptest::prelude::*;

    fn base_module(body: &str, data: Option<&str>) -> Vec<u8> {
        let data_decl = data
            .map(|d| format!("(memory 1) (data (i32.const 0) \"{d}\")"))
            .unwrap_or_default();
        let wat = format!(
            "(module (import \"kernel\" \"emit_structured_claim\" (func $emit (param i32 i32))) {data_decl} (func (export \"run\") {body}))"
        );
        wat::parse_str(&wat).expect("wat")
    }

    fn insert_meta_before_code_section(wasm: &[u8], payload: &str) -> Vec<u8> {
        fn enc(mut v: u32, out: &mut Vec<u8>) {
            loop {
                let mut b = (v & 0x7f) as u8;
                v >>= 7;
                if v != 0 {
                    b |= 0x80;
                }
                out.push(b);
                if v == 0 {
                    break;
                }
            }
        }
        fn dec(bytes: &[u8], at: &mut usize) -> Option<u32> {
            let (mut v, mut s) = (0u32, 0);
            while *at < bytes.len() {
                let b = bytes[*at];
                *at += 1;
                v |= u32::from(b & 0x7f) << s;
                if b & 0x80 == 0 {
                    return Some(v);
                }
                s += 7;
                if s > 28 {
                    break;
                }
            }
            None
        }
        let mut out = wasm[..8].to_vec();
        let mut i = 8;
        let mut inserted = false;
        while i < wasm.len() {
            let id = wasm[i];
            i += 1;
            let mut j = i;
            let Some(sz) = dec(wasm, &mut j) else {
                return wasm.to_vec();
            };
            let hdr = &wasm[i..j];
            i = j;
            let end = i + sz as usize;
            if !inserted && id == 10 {
                let mut cp = Vec::new();
                enc(4, &mut cp);
                cp.extend_from_slice(b"meta");
                cp.extend_from_slice(payload.as_bytes());
                out.push(0);
                let mut sh = Vec::new();
                enc(cp.len() as u32, &mut sh);
                out.extend_from_slice(&sh);
                out.extend_from_slice(&cp);
                inserted = true;
            }
            out.push(id);
            out.extend_from_slice(hdr);
            out.extend_from_slice(&wasm[i..end]);
            i = end;
        }
        out
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]

        #[test]
        fn prop_lane_controls_fp_and_loop_rules(use_fp in any::<bool>(), use_loop in any::<bool>()) {
            let mut body = String::from("nop");
            if use_fp { body.push_str(" f32.const 1.0 drop"); }
            if use_loop { body.push_str(" (loop nop)"); }
            let mut high = AspecPolicy::default();
            let low = AspecPolicy { lane: AspecLane::LowAssurance, float_policy: FloatPolicy::Allow, ..AspecPolicy::default() };
            high.max_loop_bound = 1;
            let high_ok = verify_aspec(&base_module(&body, None), &high).ok;
            let low_ok = if use_loop {
                let m = insert_meta_before_code_section(&base_module(&body, None), "loop_bound:1");
                verify_aspec(&m, &low).ok
            } else {
                verify_aspec(&base_module(&body, None), &low).ok
            };
            if use_fp || use_loop { prop_assert!(low_ok || !high_ok); }
        }

        #[test]
        fn prop_import_allowlist_enforced(name in "[a-z]{1,6}") {
            let bad = wat::parse_str(format!("(module (import \"evil\" \"{}\" (func)) (import \"kernel\" \"emit_structured_claim\" (func (param i32 i32))) (func (export \"run\") nop))", name)).expect("wat");
            prop_assert!(!verify_aspec(&bad, &AspecPolicy::default()).ok);
        }

        #[test]
        fn prop_data_segment_cap_enforced(len in 0usize..2048usize) {
            let data = "a".repeat(len);
            let module = base_module("nop", Some(&data));
            let p = AspecPolicy { max_data_segment_bytes: len as u64, ..AspecPolicy::default() };
            prop_assert!(verify_aspec(&module, &p).ok);
            let p_fail = AspecPolicy { max_data_segment_bytes: len.saturating_sub(1) as u64, ..AspecPolicy::default() };
            prop_assert_eq!(verify_aspec(&module, &p_fail).ok, len == 0);
        }

        #[test]
        fn prop_entropy_ratio_threshold_monotone(th in 0.0f64..1.0f64) {
            let low = base_module("nop", Some("aaaaaaaaaaaa"));
            let mut p = AspecPolicy { max_entropy_ratio: th, ..AspecPolicy::default() };
            let a = verify_aspec(&low, &p).ok;
            p.max_entropy_ratio = (th + 0.1).min(1.0);
            let b = verify_aspec(&low, &p).ok;
            if a { prop_assert!(b); }
        }

        #[test]
        fn prop_cyclomatic_complexity_threshold(th in 1u64..4u64) {
            let m = base_module("(if (i32.const 1) (then nop)) (br_if 0 (i32.const 1))", None);
            let p1 = AspecPolicy { max_cyclomatic_complexity: th, ..AspecPolicy::default() };
            let p2 = AspecPolicy { max_cyclomatic_complexity: th + 1, ..AspecPolicy::default() };
            let r1 = verify_aspec(&m, &p1).ok;
            let r2 = verify_aspec(&m, &p2).ok;
            if r1 { prop_assert!(r2); }
        }

        #[test]
        fn prop_output_proxy_threshold(max_out in 0u32..16u32) {
            let m = base_module("nop", None);
            let p = AspecPolicy { max_output_bytes: max_out, ..AspecPolicy::default() };
            let r = verify_aspec(&m, &p);
            prop_assert_eq!(r.ok, r.instruction_count <= u64::from(max_out) * 10);
        }

        #[test]
        fn prop_loop_bound_enforced_when_marker_present(bound in 0u64..4u64, cap in 0u64..4u64) {
            let mut p = AspecPolicy { lane: AspecLane::LowAssurance, float_policy: FloatPolicy::Allow, max_loop_bound: cap, ..AspecPolicy::default() };
            p.max_output_bytes = 1024;
            let m = insert_meta_before_code_section(&base_module("(loop nop)", None), &format!("loop_bound:{}", bound));
            let ok = verify_aspec(&m, &p).ok;
            prop_assert_eq!(ok, bound <= cap);
        }

        #[test]
        fn prop_heavy_lane_flag_threshold(cap in 1u64..100u64) {
            let m = base_module("(if (i32.const 1) (then nop))", None);
            let p = AspecPolicy { kolmogorov_proxy_cap: cap, ..AspecPolicy::default() };
            let r = verify_aspec(&m, &p);
            prop_assert_eq!(r.heavy_lane_flag, r.kolmogorov_proxy_bits > cap as f64);
        }
    }
}
