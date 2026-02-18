# Testing Evidence

Run the full production gate locally with:

```bash
./scripts/test_evidence.sh
```

This executes formatting, clippy, workspace tests, and coverage generation with an enforced **95% line coverage** floor.

Coverage artifact output:

- `target/coverage.lcov`

In CI, this script is used as the single gate so logs and failures map directly to one reproducible command.
