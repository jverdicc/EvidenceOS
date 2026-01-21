# Testing

Run:

```bash
pytest
ruff check .
mypy src
```

All protocol-critical components are test-covered:

- deterministic hashing
- signature verification
- quorum enforcement
- capsule verification
- Merkle inclusion proofs
