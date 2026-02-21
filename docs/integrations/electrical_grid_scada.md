---
# [Domain] Integration Guide

## Overview
See docs/INTEGRATION_PATTERNS.md for the macro pattern. 
This guide provides the concrete UVP lifecycle mapping and 
configuration for [Domain].

## UVP Lifecycle Mapping

| UVP Stage | [Domain] Equivalent | Type-level Input | 
Type-level Output |
|---|---|---|---|
| CreateClaim | | | |
| CommitArtifacts | | | |
| FreezeGates | | | |
| SealClaim | | | |
| ExecuteClaim | | | |
| FROZEN | | | |

## Example Claim (JSON)
```json
{
  "schema_id": "[domain]-claim.v1",
  "claim_id": "",
  "claim_name": "",
  "oracle_id": "",
  "topic_signals": []
}
```

## Key Configuration Parameters
- oracle_num_symbols: 
- k_budget: 
- alpha: 
- nullspec_kind: 

## Deployment Notes
Stub — to be completed.

## See Also
- docs/INTEGRATION_PATTERNS.md
- docs/threat_model_worked_example.md
---
