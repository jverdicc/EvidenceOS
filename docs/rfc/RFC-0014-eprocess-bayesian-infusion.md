# RFC-0014: E-Process Bayesian Infusion

## Summary

This RFC introduces Bayesian prior infusion for e-value acceptance. The Judge and
Evidence Process (EProcess) compute a prior-aware effective threshold that is
**only tighter, never looser**, ensuring conservative decisions.

## Policy

- The prior must be in **(0, 1]**. Missing prior defaults to **1.0**.
- The multiplier is defined as: `multiplier(prior) = clamp(1/prior, min=1, max=1e6)`.
- Acceptance requires: `e_value >= (1/alpha) * multiplier(prior)`.
- If the prior is invalid, the system must fail closed (error).

## Ledger / Recordkeeping

The Evidence Process records:

- `prior`
- `prior_multiplier`
- `effective_threshold`

These fields are captured in a deterministic EProcess record for downstream
ledgering or audit trails.

## Rationale

A lower prior indicates a more skeptical stance. By tightening the threshold
based on the inverse prior, we preserve frequentist validity while enforcing
conservative acceptance under low prior belief. The clamp prevents runaway
threshold inflation while remaining monotone in the prior.
