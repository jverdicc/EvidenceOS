.PHONY: fmt lint test test-evidence audit

fmt:
	cargo fmt --all

lint:
	mkdir -p artifacts
	bash -o pipefail -c 'cargo clippy --workspace --all-targets --all-features -- -D warnings 2>&1 | tee artifacts/lint.log'

test:
	cargo test --workspace --all-targets --all-features

test-evidence:
	./scripts/test_evidence.sh

audit:
	mkdir -p artifacts
	bash -o pipefail -c 'cargo audit 2>&1 | tee artifacts/audit.log'
