# Blackbox Demo: Transcript → Ledger → Freeze

This report is generated from a precomputed, sanitized transcript.
It demonstrates canonical outputs, k-budget accumulation, and freeze escalation behavior.

- Demo: `toy_blackbox_transcript`
- Configured k budget: `8.00` bits

| Step | call_id | oracle_name | canonical output | alphabet_size | charge Δk (bits) | cumulative k | budget remaining | DiscOS return |
| --- | --- | --- | --- | ---: | ---: | ---: | ---: | --- |
| 1 | `c01` | `quality_oracle` | `Q_BUCKET_MED` | 4 | 2.00 | 2.00 | 6.00 | `PASS` canonical `Q_BUCKET_MED` + receipt |
| 2 | `c02` | `quality_oracle` | `Q_BUCKET_MED` | 4 | 2.00 | 4.00 | 4.00 | `PASS` canonical `Q_BUCKET_MED` + receipt |
| 3 | `c03` | `safety_oracle` | `S_FLAG_LOW` | 8 | 3.00 | 7.00 | 1.00 | `PASS` canonical `S_FLAG_LOW` + receipt |
| 4 | `c04` | `robustness_oracle` | `R_BAND_2` | 16 | 4.00 | 11.00 | 0.00 | `FROZEN` + escalation receipt |
| 5 | `c05` | `quality_oracle` | `Q_BUCKET_HIGH` | 4 | 2.00 | 13.00 | 0.00 | `FROZEN` + escalation receipt |

## Outcome

Freeze/escalation begins at step **4** when cumulative `k` reaches the configured budget.

## Notes

- This is a defensive demonstration only; it uses abstract symbols and precomputed data.
- No extraction algorithm, optimization loop, or real holdout interaction is included.
