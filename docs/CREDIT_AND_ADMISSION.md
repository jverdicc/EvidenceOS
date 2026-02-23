# Access Credit and Staked Admission

## Status
Architecture specified. The EvidenceOS daemon enforces 
credit spending at claim execution boundaries. Credit 
minting, principal identity management, and stake 
accounting are operator-provided external dependencies.

## What the Daemon Enforces
- Per-claim credit deduction at ExecuteClaimV2
- Rejection when credit balance is insufficient
- Credit spend recorded in ETL capsule

## What the Operator Must Provide
An external Credit Service that satisfies this contract:

### gRPC Interface (required)
```protobuf
service CreditService {
  rpc GetBalance(GetBalanceRequest) 
    returns (BalanceResponse);
  rpc DeductCredit(DeductCreditRequest) 
    returns (DeductResponse);
  rpc MintCredit(MintCreditRequest) 
    returns (MintResponse);
}

message GetBalanceRequest {
  string principal_id = 1;
}

message BalanceResponse {
  string principal_id = 1;
  double credit_balance = 2;
  string epoch_id = 3;
}

message DeductCreditRequest {
  string principal_id = 1;
  string claim_id = 2;
  double amount = 3;
  string idempotency_key = 4;
}

message DeductResponse {
  bool success = 1;
  double remaining_balance = 2;
  string rejection_reason = 3;
}

message MintCreditRequest {
  string operator_id = 1;
  string principal_id = 2;
  double amount = 3;
  string reason_code = 4;
}

message MintResponse {
  bool success = 1;
  double new_balance = 2;
}
```

### Config file alternative (dev/small deployments)
If EVIDENCEOS_CREDIT_BACKEND=config_file, the daemon
reads credit balances from:
  state_dir/credit_balances.json
Format:
```json
{
  "principals": {
    "<principal_id>": {
      "balance": 1000.0,
      "epoch_id": "<epoch_id>"
    }
  }
}
```
This mode is NOT suitable for production multi-operator
deployments. Use gRPC backend for institutional use.

## Degressive Stake Curve (paper reference)
Per UVP paper Section 9.4, credits should be minted
via a degressive curve:
  C(S) = C_floor + κ × ln(1 + (S - B) / S0)
where B is the admission bond, S is total stake,
S0 sets scale, κ controls slope.

The daemon does not enforce the curve shape. The 
operator Credit Service is responsible for implementing
this policy before minting.

## Anti-Sybil Requirement
Operators MUST enforce that splitting stake across
n identities, each paying bond B, yields at most:
  C_total(n) ≤ (κ × S_tot / S0) + n × C_floor
              - n × (κ × B / S0)

The daemon enforces budget depletion per claim.
It does not detect or prevent Sybil identity splits.
Identity-level Sybil resistance requires operator
governance (admission bonds, KYC, or stake escrow).

## Audit Trail
Every credit deduction is recorded in the ETL capsule
under the field access_credit_spent. Operators can
reconstruct total spend per principal by scanning ETL.

## Configuration
Set in daemon config or environment:
  EVIDENCEOS_CREDIT_BACKEND=grpc|config_file|none
  EVIDENCEOS_CREDIT_SERVICE_URL=<grpc endpoint>
  EVIDENCEOS_CREDIT_FLOOR=<float, default 0.0>

If EVIDENCEOS_CREDIT_BACKEND=none (default), the daemon
skips credit enforcement. Production deployments MUST
set a real backend.
