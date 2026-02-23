.PHONY: setup reproduce verify verify-lite clean

ROOT_DIR := $(abspath $(CURDIR)/../..)
OUT_DIR := $(CURDIR)/out
ORIGINAL := $(CURDIR)/original_python

setup:
	cd $(ROOT_DIR) && cargo fetch --locked
	cd $(ROOT_DIR) && cargo build --workspace --locked

reproduce:
	python3 $(ORIGINAL)/run_all.py --repo-root $(ROOT_DIR) --out-dir $(OUT_DIR)

verify: reproduce
	python3 $(ORIGINAL)/verify_outputs.py --out-dir $(OUT_DIR) --expected-dir $(ORIGINAL)/expected --tolerance 1e-9

verify-lite:
	python3 $(ORIGINAL)/run_all.py --repo-root $(ROOT_DIR) --out-dir $(OUT_DIR) --quick
	python3 $(ORIGINAL)/verify_outputs.py --out-dir $(OUT_DIR) --expected-dir $(ORIGINAL)/expected --tolerance 1e-9

clean:
	rm -rf $(OUT_DIR)
	mkdir -p $(OUT_DIR)
