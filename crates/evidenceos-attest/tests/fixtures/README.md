# SEV-SNP fixture notes

This directory stores attestation verification fixtures:
- `sev_snp_policy.json`: sample policy with allowed measurements and minimum TCB values.

Unit tests in `src/lib.rs` construct known-good and known-bad SEV-SNP reports and cert chains in-memory to avoid embedding private keys in repo fixtures.
