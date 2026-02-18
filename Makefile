.PHONY: fmt lint test test-evidence audit

fmt:
	cargo fmt --all

lint:
	mkdir -p artifacts
	bash -o pipefail -c 'cargo clippy --workspace --all-targets --all-features -- -D warnings 2>&1 | tee artifacts/lint.log'

test:
	cargo test --workspace --all-targets --all-features

test-evidence:
	mkdir -p artifacts
	cargo llvm-cov --all-features --workspace --lcov --output-path artifacts/coverage.lcov
	cargo llvm-cov --all-features --workspace --html --output-dir artifacts/coverage-html
	bash -o pipefail -c 'cargo test --workspace --all-targets --all-features -- --nocapture | tee artifacts/test.log'
	bash -o pipefail -c 'cargo clippy --workspace --all-targets --all-features -- -D warnings 2>&1 | tee artifacts/lint.log'
	@core_cov=$$(awk 'BEGIN{hit=0;found=0} /^SF:.*crates\/evidenceos-core\// {found=1; next} /^SF:/ {found=0} found && /^DA:/ {split($$0,a,","); if (a[2]>0) hit++} END{if(hit==0) print 0; else print hit}' artifacts/coverage.lcov); \
	core_lines=$$(awk 'BEGIN{tot=0;found=0} /^SF:.*crates\/evidenceos-core\// {found=1; next} /^SF:/ {found=0} found && /^DA:/ {tot++} END{print tot}' artifacts/coverage.lcov); \
	daemon_cov=$$(awk 'BEGIN{hit=0;found=0} /^SF:.*crates\/evidenceos-daemon\// {found=1; next} /^SF:/ {found=0} found && /^DA:/ {split($$0,a,","); if (a[2]>0) hit++} END{if(hit==0) print 0; else print hit}' artifacts/coverage.lcov); \
	daemon_lines=$$(awk 'BEGIN{tot=0;found=0} /^SF:.*crates\/evidenceos-daemon\// {found=1; next} /^SF:/ {found=0} found && /^DA:/ {tot++} END{print tot}' artifacts/coverage.lcov); \
	core_pct=$$(awk -v h=$$core_cov -v t=$$core_lines 'BEGIN{if(t==0) print 0; else printf "%.2f", (h/t)*100}'); \
	daemon_pct=$$(awk -v h=$$daemon_cov -v t=$$daemon_lines 'BEGIN{if(t==0) print 0; else printf "%.2f", (h/t)*100}'); \
	echo "core coverage: $$core_pct% ($$core_cov/$$core_lines)"; \
	echo "daemon coverage: $$daemon_pct% ($$daemon_cov/$$daemon_lines)"; \
	awk -v c=$$core_pct 'BEGIN{if(c+0 < 90.0) {print "core coverage below 90%"; exit 1}}'; \
	awk -v d=$$daemon_pct 'BEGIN{if(d+0 < 80.0) {print "daemon coverage below 80%"; exit 1}}'
	@(! rg -n "^\s*#\[ignore\]" crates)

audit:
	mkdir -p artifacts
	bash -o pipefail -c 'cargo audit 2>&1 | tee artifacts/audit.log'
