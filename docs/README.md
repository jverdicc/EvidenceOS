# Documentation Index

Key starting points:

- [Start here: threat model walkthrough](threat_model_worked_example.md)
- [UVP black-box interface (service contract)](uvp_blackbox_interface.md)
- [Threat Model by Example (Blackbox Walkthrough)](THREAT_MODEL_BLACKBOX.md)
- [Operation-Level Security](OPERATION_LEVEL_SECURITY.md)
- [Dual-Use and Misuse Policy](DUAL_USE_AND_MISUSE.md)
- [Architecture Diagrams](ARCHITECTURE_DIAGRAMS.md)
- [ETL FAQ (why append-only transparency log, not blockchain)](ETL_FAQ.md)
- [ETL indexer (SQLite analytics acceleration)](ETL_INDEXER.md)
- [Epistemic trial harness (units, endpoints, competing risks)](EPISTEMIC_TRIAL_HARNESS.md)
- [Oracle design and controls](ORACLES.md)
- [Testing evidence](TEST_EVIDENCE.md)
- [Coverage matrix](TEST_COVERAGE_MATRIX.md)
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
