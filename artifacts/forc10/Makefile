.PHONY: setup reproduce figures verify clean

ROOT_DIR := $(abspath $(CURDIR)/../..)
OUT_DIR := $(CURDIR)/out

setup:
	cd $(ROOT_DIR) && cargo fetch --locked
	cd $(ROOT_DIR) && cargo build --workspace --locked

reproduce:
	python3 $(CURDIR)/scripts/reproduce.py --repo-root $(ROOT_DIR) --out-dir $(OUT_DIR)

figures:
	python3 $(CURDIR)/scripts/figures.py --out-dir $(OUT_DIR)

verify: reproduce figures
	python3 $(CURDIR)/scripts/verify.py --out-dir $(OUT_DIR) --golden-dir $(CURDIR)/golden --tolerance 1e-9

clean:
	rm -rf $(OUT_DIR)
	mkdir -p $(OUT_DIR)
