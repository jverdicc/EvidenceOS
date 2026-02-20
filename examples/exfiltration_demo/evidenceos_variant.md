# EvidenceOS-style exfiltration-resistant scoring interface

This demo keeps the same *shape* as a prediction-scoring API, but inserts policy controls
that intentionally reduce information leakage per query.

## Controls modeled

1. **Quantized output**
   - Raw accuracy is rounded to coarse buckets (`0.10` step in the mock).
   - A one-bit probe no longer yields a stable ±`1/N` signal.

2. **Hysteresis threshold**
   - Small output changes are suppressed (`0.07` margin in the mock).
   - Repeated near-identical probes collapse to the previous reported value, reducing incremental side-channel signal.

3. **Transcript budget**
   - The oracle enforces a hard query cap (`32` in the mock for `N=64`).
   - Classic O(N) bit-flip extraction cannot complete because it needs `N+1` high-fidelity probes.

4. **Capsule-like receipts**
   - Each response includes a deterministic hash receipt over request/response metadata.
   - This mirrors EvidenceOS's emphasis on auditable transcripts without exposing raw internals.

## Expected effect on the bit-flip attack

- **Baseline oracle** (exact accuracy): attack reconstructs labels with very high accuracy.
- **EvidenceOS mock** (quantized + hysteresis + budget): attack stalls with low-confidence deltas
  and an insufficient number of accepted probes, yielding much lower recovered accuracy.

## Running

- `make demo-exfil-baseline`
- `make demo-exfil-evidenceos-mock`

CI also runs a deterministic test asserting the baseline leaks and the mock mitigates leakage.
