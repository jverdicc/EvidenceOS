# Dual-Use and Misuse Policy

EvidenceOS and DiscOS are dual-use technologies. This policy defines permitted usage, prohibited deployment patterns, and technical safeguards that default to fail-closed behavior in high-risk contexts.

## Intended Use

EvidenceOS is intended to be used as a verification kernel that:

- evaluates claims under bounded, auditable interaction,
- enforces structured/canonical outputs where required,
- meters transcript leakage and evidence budgets,
- supports human oversight in high-stakes workflows.

DiscOS is intended to be used as untrusted orchestration/userland that prepares candidate claims and consumes kernel responses without widening the trust boundary.

## Prohibited Deployments

The following are prohibited:

- Deploying high-risk domain evaluations with free-text outputs in production.
- Running high-risk evaluations without deterministic schema validation and canonicalization.
- Using EvidenceOS/DiscOS to generate, optimize, or operationalize real-world harmful instructions.
- Removing human review checkpoints for high-stakes operational decisions.
- Disabling or bypassing enforcement controls that route high-risk workloads into stricter assurance lanes.

## Human-in-the-Loop Requirements (High-Risk Domains)

For high-risk domains (including CBRN and similarly sensitive operational domains):

- A trained human reviewer must approve deployment gating decisions.
- Automated outputs must be treated as decision support, not autonomous action authorization.
- Escalations into heavy-assurance lanes must be reviewable and auditable.
- Incident and rejection logs must be retained and monitored.

## Structured Output Requirements (High-Risk Domains)

For high-risk domains:

- Output schema must be `CBRN_SC_V1` (`cbrn-sc.v1`).
- Legacy/free-text schemas are not permitted in production.
- Structured output canonicalization and validation are mandatory.

## Enforcement Knobs (Default-Secure)

EvidenceOS provides enforcement controls that should remain enabled in production:

- `EVIDENCEOS_REQUIRE_STRUCTURED_OUTPUTS=true`
- `EVIDENCEOS_REQUIRE_STRUCTURED_OUTPUTS_DOMAINS=CBRN`
- `EVIDENCEOS_DENY_FREE_TEXT_OUTPUTS=true` in production (`EVIDENCEOS_PRODUCTION_MODE=1`)
- `EVIDENCEOS_FORCE_HEAVY_LANE_ON_DOMAIN=CBRN`

Runtime behavior:

- If a high-risk domain is requested with non-`CBRN_SC_V1` schema, claim creation is rejected.
- If a high-risk domain is requested with a structured schema but non-heavy lane, lane is force-escalated to heavy.

Production startup hard-fail behavior:

- When `EVIDENCEOS_PRODUCTION_MODE=1`, daemon startup fails closed (non-zero exit) if any of the following insecure toggles are enabled via CLI or environment:
  - `--allow-plaintext-holdouts` or `EVIDENCEOS_ALLOW_PLAINTEXT_HOLDOUTS=1`
  - `--insecure-synthetic-holdout` or `EVIDENCEOS_INSECURE_SYNTHETIC_HOLDOUT=1`
  - `--offline-settlement-ingest` or `EVIDENCEOS_OFFLINE_SETTLEMENT_INGEST=1` **without** `--offline-settlement-ingest-operator-ack`
- Startup error messages are explicit:
  - `refusing startup: EVIDENCEOS_PRODUCTION_MODE=1 forbids plaintext holdouts; disable --allow-plaintext-holdouts and EVIDENCEOS_ALLOW_PLAINTEXT_HOLDOUTS`
  - `refusing startup: EVIDENCEOS_PRODUCTION_MODE=1 forbids insecure synthetic holdouts; disable --insecure-synthetic-holdout and EVIDENCEOS_INSECURE_SYNTHETIC_HOLDOUT`
  - `refusing startup: offline settlement ingest bypass requires --offline-settlement-ingest-operator-ack when EVIDENCEOS_PRODUCTION_MODE=1`
- In non-production mode, these flags remain available for controlled development/testing and are logged as unsafe for production.

## Safe Demonstration Policy (DiscOS-facing)

Demonstrations must:

- use synthetic or toy data,
- avoid operationally actionable harmful instructions,
- focus on verification semantics, auditability, and bounded interaction controls.

Demonstrations must not:

- provide procedural instructions for real-world harm,
- simulate deployment-ready offensive playbooks,
- include secrets, credentials, or sensitive holdout data.
