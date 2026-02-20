# NullSpec governance

NullSpec is the governance contract that pins the pre-committed null hypothesis (`H0`) and e-process recipe to an oracle/holdout lifecycle.

## Lifecycle
1. `evidenceosctl nullspec create` builds a canonical `NullSpecContractV1` from calibration buckets (or operator-specified parameters).
2. `evidenceosctl nullspec install` stores the contract in `data-dir/nullspec/<id>.json`.
3. `evidenceosctl nullspec activate` rotates active mapping for `(oracle_id, holdout_handle)`.
4. Claims fail closed unless an active, unexpired, resolution-hash-matching NullSpec is pinned.

## Parametric vs non-parametric
- Parametric: `ParametricBernoulli` + fixed-alt likelihood ratio.
- Non-parametric: `DiscreteBuckets` + `DirichletMultinomialMixture`, estimated from calibration buckets.

## Signing and audit
Contracts carry `created_by` and `signature_ed25519` over canonical bytes (excluding signature field). Install/activate operations emit governance records for ETL-side auditing.

This enforces the paper guarantee that the tested null is pre-committed and tamper-evident.
