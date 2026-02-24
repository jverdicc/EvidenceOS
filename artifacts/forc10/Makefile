.PHONY: setup reproduce verify verify-lite verify-full fetch-full-artifacts clean

ROOT_DIR := $(abspath $(CURDIR)/../..)
OUT_DIR := $(CURDIR)/out
ORIGINAL := $(CURDIR)/original_python
MANIFEST := $(CURDIR)/FULL_ARTIFACT_MANIFEST.json
MODE ?= quick
FULL_SOURCE ?= remote
FULL_LOCAL_ARCHIVE ?=

setup:
	cd $(ROOT_DIR) && cargo fetch --locked
	cd $(ROOT_DIR) && cargo build --workspace --locked

reproduce:
	python3 $(ORIGINAL)/run_all.py --repo-root $(ROOT_DIR) --out-dir $(OUT_DIR)

fetch-full-artifacts:
	bash $(ROOT_DIR)/scripts/fetch_forc10_artifacts.sh --manifest $(MANIFEST) --source $(FULL_SOURCE) $(if $(FULL_LOCAL_ARCHIVE),--local-archive $(FULL_LOCAL_ARCHIVE),)

verify-full:
	@echo "[forc10] mode=FULL"
	@echo "[forc10] reproducing: all FORC10 experiments implemented in artifacts/forc10/original_python + Table 1 outputs"
	$(MAKE) fetch-full-artifacts
	python3 $(ORIGINAL)/run_all.py --repo-root $(ROOT_DIR) --out-dir $(OUT_DIR)
	python3 $(ORIGINAL)/verify_outputs.py --out-dir $(OUT_DIR) --expected-dir $(ORIGINAL)/expected --tolerance 1e-9
	@echo "[forc10] completed FULL reproduction: raw/results.{json,csv} and figures/table_1.{csv,md}"

verify-lite:
	@echo "[forc10] mode=QUICK"
	@echo "[forc10] reproducing: deterministic schema/golden drift checks for scenario + probing metrics"
	python3 $(ORIGINAL)/run_all.py --repo-root $(ROOT_DIR) --out-dir $(OUT_DIR) --quick
	python3 $(ORIGINAL)/verify_outputs.py --out-dir $(OUT_DIR) --expected-dir $(ORIGINAL)/expected --tolerance 1e-9
	@echo "[forc10] completed QUICK verification: drift check against expected results"

verify:
	@if [ "$(MODE)" = "full" ]; then \
		$(MAKE) verify-full; \
	else \
		$(MAKE) verify-lite; \
	fi

clean:
	rm -rf $(OUT_DIR)
	mkdir -p $(OUT_DIR)
