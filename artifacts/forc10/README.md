# FORC10 Artifact Reproduction Harness

This directory provides two explicit reproduction modes for reviewers.

## QUICK mode (CI-friendly, no network)

```bash
make -C artifacts/forc10 verify MODE=quick
```

What QUICK reproduces:
- deterministic execution of the FORC10 scenario + probing experiments in `--quick` mode,
- schema/golden drift checks against committed expected outputs,
- generated outputs: `results.json`, `results.csv`, `table_1.csv`, `table_1.md`.

QUICK never downloads from the network.

## FULL mode (paper-faithful)

```bash
make -C artifacts/forc10 verify MODE=full
```

What FULL reproduces:
- downloads the authoritative artifact bundle from the DOI/release URL,
- validates the bundle against pinned SHA-256 checksums in `FULL_ARTIFACT_MANIFEST.json`,
- runs the full deterministic paper pipeline,
- verifies generated outputs against committed expected artifacts.

Manual fetch command:

```bash
bash scripts/fetch_forc10_artifacts.sh --source remote
```

If you already downloaded the archive, you can avoid re-downloading while still enforcing checksum pinning:

```bash
bash scripts/fetch_forc10_artifacts.sh --source local --local-archive /path/to/forc10-paper-artifact.tar.gz
```

The fetch script refuses to continue if checksums mismatch the committed manifest.

## Single default command

```bash
make -C artifacts/forc10 verify
```

Default mode is `MODE=quick`.
`make ... verify` prints the mode and exactly what was reproduced.

## Coverage and exclusions

Reproduced artifacts:
- `artifacts/forc10/out/raw/results.json`
- `artifacts/forc10/out/raw/results.csv`
- `artifacts/forc10/out/figures/table_1.csv`
- `artifacts/forc10/out/figures/table_1.md`

Explicit exclusions:
- No additional figure/table generators beyond Table 1 are present in the repository-aligned FORC10 experiment harness.
