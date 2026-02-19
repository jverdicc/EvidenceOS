# Maintainers and Governance

This file describes how EvidenceOS maintenance decisions are made for this repository.

## Current maintainers

- EvidenceOS Maintainers Team (primary review and release responsibility)

Contact routes:

- General/project process: GitHub issues or discussions in this repository
- Security: security@evidenceos.org
- Conduct: conduct@evidenceos.org

## Maintainer responsibilities

Maintainers are responsible for:

- triaging issues and pull requests,
- enforcing contribution standards in `CONTRIBUTING.md`,
- preserving deterministic and fail-closed protocol properties,
- ensuring CI gates and test evidence requirements remain enforced,
- managing release and documentation quality.

## Decision model

- Routine changes: maintainer review and approval in PR.
- Sensitive protocol-surface or security-affecting changes: at least two maintainer approvals when possible.
- In case of disagreement: default to conservative/fail-closed behavior and request additional tests.

## Change control priorities

When evaluating changes, maintainers prioritize the repository guidance in `AGENTS.md`:

1. determinism and canonicalization integrity,
2. panic-free request/runtime behavior,
3. strict input validation for network-exposed APIs,
4. no secret/raw payload leakage in logs,
5. CI/test evidence integrity.

## Contributor progression

Regular contributors may be invited as maintainers based on:

- sustained high-quality contributions,
- strong review participation,
- adherence to testing and documentation standards,
- demonstrated security and protocol rigor.

## Operational references

Maintainers and contributors should use:

- `TESTING_EVIDENCE.md`
- `docs/TEST_EVIDENCE.md`
- `docs/TEST_COVERAGE_MATRIX.md`

These documents define expected verification evidence and coverage mapping used in review.
