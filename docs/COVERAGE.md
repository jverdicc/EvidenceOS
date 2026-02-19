# Coverage Summary

CI now runs `cargo llvm-cov --workspace --all-features --summary-only` in addition to fmt/clippy/test checks.
Coverage artifacts are uploaded by GitHub Actions in the `coverage-lcov` artifact.
