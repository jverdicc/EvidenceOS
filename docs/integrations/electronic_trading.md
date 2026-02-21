# Electronic Trading Integration Guide

## Overview
In high-frequency and medium-frequency trading (HFT/MFT), quantitative researchers constantly test new alpha signals against historical market data. Without strict epistemological boundaries, strategies inevitably overfit to the backtest (adaptivity leakage) or enter destructive feedback loops in live markets. EvidenceOS maps natively to standard quantitative finance infrastructure: the leakage budget (k) bounds backtest overfitting, and evidence wealth (W) enforces deterministic drawdown limits at the live execution gateway.

## UVP Lifecycle Mapping
| UVP Stage | Electronic Trading Equivalent | Type-level Input | Type-level Output |
|---|---|---|---|
| CreateClaim | Allocate Strategy Risk Budget | `StrategySpec`, `RiskLimits` | `ClaimID`, Initial `W` & `k` |
| CommitArtifacts | Lock Model Weights & Source Code | `CodeHash`, `AlphaHIR` | `CommitmentReceipt` |
| FreezeGates | Pre-Trade Risk Checks (Fat-finger) | `PositionLimits` | `AdmissibilityStatus` |
| SealClaim | Deploy to Prod / Connect to FIX | `ExchangeSessionID` | `SealedEnv` |
| ExecuteClaim | Evaluate Tick Data / Submit Order | `MarketTick`, `OrderTicket` | `FillReceipt`, `k_depletion`, `W_update` |
| FROZEN | Trigger Circuit Breaker / Pull Orders | `DrawdownViolationEvent` | `DisconnectAck`, `FROZEN` state |

## Example Claim (JSON)
```json
{
  "schema_id": "electronic_trading-claim.v1",
  "claim_id": "alpha_momentum_nq_v4",
  "claim_name": "NASDAQ Order Book Imbalance Momentum",
  "oracle_id": "cme_market_data_gateway",
  "topic_signals": [
    "bid_ask_spread",
    "level_2_volume_imbalance",
    "trade_tape_velocity"
  ],
  "expected_sharpe": "2.1",
  "max_drawdown_bps": 500
}
```

## Key Configuration Parameters
- oracle_num_symbols: 3 (e.g., Order Action: BUY, SELL, HOLD)
- k_budget: 1024.0 (Total allowable bits of adaptivity leakage during the research phase before the strategy is deemed overfit and rejected for production).
- alpha: 0.01 (1% probability of false certification under the null hypothesis; defines the strictness of the statistical test for alpha).
- nullspec_kind: "random_walk_with_drift" (The pre-committed mathematical baseline the strategy must consistently beat to maintain positive Evidence Wealth W).

## Deployment Notes
The W to Drawdown Mapping: In standard finance, a max drawdown limit is a static dollar amount. In EvidenceOS, Evidence Wealth (W) fluctuates based on statistical significance. If the strategy's predictive edge decays to random chance, W depletes rapidly, triggering a FROZEN halt before maximum capital drawdown is reached.

The k to Signal-Decay Mapping: Every time a quant researcher tweaks a parameter and re-runs the backtest on the holdout set, the k budget drains. Once the budget is exhausted, EvidenceOS mathematically guarantees that any further "improvements" to the Sharpe ratio are purely statistical illusions (overfitting). The system locks the dataset epoch, forcing the researcher to wait for new out-of-sample data.

Latency Considerations: In HFT, the ExecuteClaim loop must operate in microseconds. The EvidenceOS Conservation Ledger should be implemented alongside the FPGA/NIC level risk checks, processing deterministic W/k accounting without blocking the critical path to the matching engine.

## See Also
- docs/INTEGRATION_PATTERNS.md
- docs/threat_model_worked_example.md
