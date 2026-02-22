# PLN Production Profile

This document defines the production threat model and current implementation scope for Path-Length Normalization (PLN) in EvidenceOS.

## Production scope (current)

EvidenceOS currently implements **runtime fuel normalization only**:

- Execution fuel is normalized to at least a configured target (`pln_target_fuel`), then
- Rounded up to deterministic epoch boundaries (`epoch_size`) before settlement/accounting.

This is implemented as **fuel-epoch rounding** in the daemon runtime path.

EvidenceOS does **not** currently implement compile-time CFG branch-cost equalization or a WASM rewriting pass that inserts branch-padding blocks.

## Threat model and mitigation boundary

### Mitigated (partially)

- Reduces leakage from coarse per-claim execution-cost differences by collapsing observed totals into deterministic epoch buckets.
- Reduces straightforward “short vs long path” fuel distinguishability when branch deltas are within an epoch bucket.

### Not mitigated

- Fine-grained microarchitectural timing channels (cache, branch predictor, speculative behavior, scheduler jitter).
- Intra-bucket branch-cost differences when adversaries can observe side channels outside normalized fuel totals.
- Compile-time structural branch differences in WASM control-flow graphs (no static branch equalization pass yet).

## Operational requirements

- Keep `epoch_size` and PLN targets stable for a deployment profile.
- Validate `pln_target_fuel <= pln_max_fuel`; fail closed if max fuel is exceeded.
- Treat PLN as one layer alongside ASPEC admissibility checks and deterministic settlement.

## Paper parity note

Paper-facing language should treat PLN as:

- **Implemented today:** runtime fuel normalization and epoch rounding.
- **Not implemented today:** compile-time CFG equalization rewrite.

Do not claim full static+runtime PLN until compile-time rewriting is added with validation tests.

## Strict PLN response-timing mode

A production hardening flag is available for externally observable timing normalization:

- `EVIDENCEOS_STRICT_PLN=true` enables response-time floor padding for execution APIs.
- `EVIDENCEOS_STRICT_PLN_FAST_EXECUTE_FLOOR_MS=<ms>` sets the fast-lane minimum response floor.
- `EVIDENCEOS_STRICT_PLN_HEAVY_EXECUTE_FLOOR_MS=<ms>` sets the heavy-lane minimum response floor.

Padding policy is selected from declared method class + lane only; it does not depend on holdout outputs.

Tradeoffs:
- Increases tail latency and can reduce throughput under burst load.
- Improves resistance to latency-based transcript side channels at external surfaces.
