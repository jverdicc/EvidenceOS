# Documentation Index

## Recommended reading order

1. [Start here](START_HERE.md)
2. [Threat model](THREAT_MODEL_BLACKBOX.md)
3. [Paper reproduction](../README.md#case-study-distillation-style-probing-public-reporting)
4. [Epistemic trial harness](EPISTEMIC_TRIAL_HARNESS.md)
5. [API refs (daemon gRPC/IPC)](../README.md#ipc-api)
6. [Deployment](OPERATIONS.md)
7. [Security](OPERATION_LEVEL_SECURITY.md)

## Key docs

- [Start here: reader paths into EvidenceOS + DiscOS](START_HERE.md)
- [Threat model by example (blackbox walkthrough)](THREAT_MODEL_BLACKBOX.md)
- [Threat model worked example](threat_model_worked_example.md)
- [UVP black-box interface (service contract)](uvp_blackbox_interface.md)
- [Paper reproduction: case-study section in top-level README](../README.md#case-study-distillation-style-probing-public-reporting)
- [Epistemic trial harness (units, endpoints, competing risks)](EPISTEMIC_TRIAL_HARNESS.md)
- [Trial harness analysis quickstart](TRIAL_HARNESS_ANALYSIS.md)
- [Clinical trials framework quickstart (workflow + examples)](integrations/fda_clinical_trials.md)
- [API refs: daemon gRPC lifecycle + IPC methods](../README.md#ipc-api)
- [Deployment operations guide](OPERATIONS.md)
- [Dual-Use and Misuse Policy](DUAL_USE_AND_MISUSE.md)
- [Operation-Level Security](OPERATION_LEVEL_SECURITY.md)
- [Architecture Diagrams](ARCHITECTURE_DIAGRAMS.md)
- [ETL FAQ (why append-only transparency log, not blockchain)](ETL_FAQ.md)
- [ETL indexer (SQLite analytics acceleration)](ETL_INDEXER.md)
- [Oracle design and controls](ORACLES.md)
- [Testing evidence](TEST_EVIDENCE.md)
- [Coverage matrix (mechanism-level)](TEST_COVERAGE_MATRIX.md)
- [Coverage matrix (parameter-level appendix)](TEST_COVERAGE_PARAMETERS.md)
- [LangChain preflight wrapper configuration](LANGCHAIN_WRAPPER.md)

## Integration Guides
Domain-specific guides showing how UVP maps onto high-stakes 
production systems:

- [Electronic Trading](integrations/electronic_trading.md) — 
  strategy drawdown limits, signal decay, FIX engine boundary
- [FDA Clinical Trials](integrations/fda_clinical_trials.md) — 
  regulatory submission gateway, SAP as NullSpec
- [Disease Surveillance](integrations/disease_surveillance.md) — 
  outbreak alert gateway, PII protection via joint entropy
- [Electrical Grid / SCADA](integrations/electrical_grid_scada.md) — 
  control command admissibility, ASPEC whitelisting
- [Climate Modeling](integrations/climate_modeling.md) — 
  CMIP/IPCC assessment gateway, ensemble cherry-pick prevention
- [AI Leaderboards](integrations/ai_leaderboards.md) — 
  benchmark gaming prevention, topic budget depletion
- [Pharmaceutical Synthesis](integrations/pharmaceutical_synthesis.md) — 
  lab automation gateway, PhysHIR molar quantity checks
- [Autonomous Vehicles](integrations/autonomous_vehicles.md) — 
  OTA deployment gateway, edge case holdout protection
