# Regulatory Reporting and Transparency (Incident Capsules)

EvidenceOS (UVP) is a verification kernel, not an intent-inference system: it does not determine motive, diagnose a person, or perform automatic policing. It can, however, support auditable event logging by emitting deterministic, bounded, and verifiable incident records that external governance processes can review.

## What an Incident Capsule is

An **Incident Capsule** is a minimal, structured event record intended for regulated transparency and post-incident audit. The capsule should be designed to preserve verification value while minimizing sensitive content.

Proposed minimal schema:

| Field | Type | Notes |
| --- | --- | --- |
| `event_id` | UUID | Globally unique event identifier. |
| `event_time` | `object` | Includes mandatory DLC epoch; wall-clock timestamp is optional and policy-controlled. |
| `policy_oracle_id` | string | Identifier for the policy oracle/policy package that produced the decision. |
| `policy_version` | hash string | Immutable digest of active policy artifact(s) at decision time. |
| `trigger_class` | enum | High-level class only (for example: `VIOLENCE`, `SELF_HARM`, `CBRN`, `FRAUD`, `OTHER_REGULATED`). |
| `action` | enum | One of: `NONE`, `WARN`, `RESTRICT`, `FREEZE`, `ESCALATE_REVIEW`, `ESCALATE_LAW_ENFORCEMENT`. |
| `reason_codes` | enum list (bounded) | Controlled vocabulary; bounded count/size; no free-form narratives. |
| `subject_pseudonym` | string | Stable HMAC-derived pseudonym; never a raw user identifier. |
| `transcript_commitment` | hash string | Commitment to a redacted transcript or internal evidence packet (not raw chat text). |
| `etl_inclusion_proof_ref` | string/object | Reference to ETL inclusion material (receipt/proof/tree head linkage) sufficient for independent verification. |

Implementation notes:

- Keep all fields schema-validated with strict bounds (enum/domain/length) and fail closed on invalid data.
- Prefer deterministic canonical encoding for capsule serialization before commitment.
- Keep `trigger_class` coarse to reduce sensitive inference leakage.

## Privacy & lawful basis

Any deployment using incident capsules should establish a documented lawful basis and governance controls appropriate to jurisdiction and sector requirements.

Minimum controls:

- **Data minimization:** collect only the bounded structured fields needed for accountability and audit.
- **Retention limits:** define retention schedules and deletion policies for capsule-adjacent internal evidence.
- **Encryption at rest:** protect capsule stores, ETL-adjacent indices, and key material.
- **Access controls:** enforce least privilege, approval workflows, and auditable access logging.
- **Independent oversight:** support review by internal compliance and, where applicable, external regulators/auditors.

**Do not store raw chat logs in a public transparency log.**

## What this does NOT do

Incident capsules are accountability artifacts, not autonomous enforcement.

- Not a threat assessment engine.
- Not a replacement for legal/compliance teams.
- Not a guarantee of preventing attacks.

## How this relates to the paper

This design follows the UVP paper's emphasis on deterministic accounting and auditable settlement through ETL commitments. In that framing, incident handling can be represented as fail-closed, append-only evidence events that are externally verifiable.

To remain privacy-preserving and auditable at scale, capsule outputs should be **capacity-bounded structured events** (enums/hashes/references) rather than free-form narrative text. This keeps reporting composable with conservation-style controls while avoiding unnecessary disclosure.

Related references:

- [ETL FAQ](ETL_FAQ.md)
- [UVP black-box interface](uvp_blackbox_interface.md)
- [Paper vs code mapping](PAPER_VS_CODE.md)
- [Research & citation (README)](../README.md#research--citation)

> [!IMPORTANT]
> **Status:** Documentation/architecture only. Incident capsules are not yet a standardized API in the current release unless explicitly implemented.
