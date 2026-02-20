.PHONY: fmt lint test test-evidence audit blackbox-demo demo-exfil-baseline demo-exfil-evidenceos-mock test-exfil-demo

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

blackbox-demo:
	python3 examples/blackbox_demo/render_demo.py

demo-exfil-baseline:
	python3 examples/exfiltration_demo/attack_bitflip.py --mode baseline --n 64 --seed 7

demo-exfil-evidenceos-mock:
	python3 examples/exfiltration_demo/attack_bitflip.py --mode evidenceos-mock --n 64 --seed 7

test-exfil-demo:
	python3 -m unittest scripts.tests.test_exfiltration_demo
