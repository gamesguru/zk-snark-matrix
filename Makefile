SHELL=/bin/bash

# Variables
CARGO = cargo
PYTHON = python3

# Load environment variables from .env file if it exists
ifneq (,$(wildcard ./.env))
    include .env
endif

.DEFAULT_GOAL := help

.PHONY: all
all: build setup format lint test ##H Build, setup data, format, lint, and run tests

.PHONY: build
build: ##H Build the Rust project
	@echo "Building ZK-Matrix-Join"
	$(CARGO) build --release

.PHONY: demo
demo: ##H Run the ZK-Matrix-Join Simulation (Demo)
	@echo "Running ZK-Matrix-Join Demo"
	$(CARGO) run --release --bin ruma-zk -- demo

.PHONY: benchmark-lite
benchmark-lite: ##H Run Simulation with Tiny 5-Event Graph
	@echo "Running ZK-Matrix-Join Benchmark (Lite)"
	$(CARGO) run --release --bin ruma-zk -- demo --input res/ruma_bootstrap_events.json

.PHONY: benchmark-batch
benchmark-batch: ##H Run Simulation with Concise DSL Fixtures
	@echo "Running ZK-Matrix-Join Benchmark (Batch DSL)"
	$(CARGO) run --release --bin ruma-zk -- demo --batch demo

.PHONY: prove
prove: ##H Generate full Jolt STARK Proof
	@echo "Generating Jolt STARK Proof"
	RUST_LOG=info $(CARGO) run --release --bin ruma-zk -- prove

.PHONY: verify
verify: ##H Verify an existing Jolt STARK Proof
	@echo "Verifying Jolt STARK Proof"
	$(CARGO) run --release --bin ruma-zk -- verify

.PHONY: publish
publish: ##H Preview package file list and simulate a dry-run publish for ruma-zk
	@echo "Previewing packaged files for ruma-zk"
	@echo "-----------------------------------"
	cd ruma-zk && $(CARGO) package --list --allow-dirty
	@echo ""
	@echo "Simulating publish for ruma-zk (--dry-run)"
	@echo "-----------------------------------"
	cd ruma-zk && $(CARGO) publish --dry-run --allow-dirty

.PHONY: wasm
wasm: ##H Build the WebAssembly light-client Verifier
	@echo "Compiling WASM bindings"
	cd ruma-zk-wasm && wasm-pack build --target web

.PHONY: web-demo
web-demo: ##H Run a local web server to test the WASM UI
	@echo "================================================================"
	@echo " ZK-Matrix WebAssembly Server is starting!"
	@echo " Please manually open your web browser to:"
	@echo " http://localhost:8080/demo/index.html"
	@echo "================================================================"
	python3 -m http.server 8080

.PHONY: test
test: ##H Run fast Native Resolution tests (<1s)
	@echo "Running Fast Native Tests"
	$(CARGO) test -p ruma-zk -- --nocapture
	@echo "Running ruma-lean formal parity tests"
	$(CARGO) test -p ruma-lean

.PHONY: test-zk
test-zk: ##H Run the full Jolt Parity Simulation
	@echo "Running Deep Jolt Parity Simulation"
	RUST_LOG=info RAYON_NUM_THREADS=1 $(CARGO) test --release -p ruma-zk -- --ignored --nocapture --test-threads=1

.PHONY: setup
setup: ##H Combined: Fetch real Matrix data and Ruma state resolution fixtures
	@echo "Setting up project data and fixtures"
	@if [ -n "$$MATRIX_TOKEN" ]; then \
		echo "Fetching real Matrix state data from $$MATRIX_HOMESERVER"; \
		$(PYTHON) scripts/fetch_matrix_state.py; \
	else \
		echo "Skipping real Matrix fetch (MATRIX_TOKEN not set)."; \
	fi
	@echo "Ruma State Res test fixtures are checked in to res/"

.PHONY: cpu-info
cpu-info: ##H Print CPU info relevant to native target-cpu
	@echo "=== CPU Model ==="
	@grep -m1 'model name' /proc/cpuinfo 2>/dev/null || sysctl -n machdep.cpu.brand_string 2>/dev/null || echo "unknown"
	@echo "=== Architecture ==="
	@uname -a
	@echo "=== rustc Host Target ==="
	@rustc -vV | grep host
	@echo "=== rustc Native CPU ==="
	@rustc --print=cfg -C target-cpu=native 2>/dev/null | grep target_feature | sort
	@echo "=== CPU Flags [from /proc/cpuinfo] ==="
	@grep -m1 'flags' /proc/cpuinfo 2>/dev/null | tr ' ' '\n' | grep -E 'avx|sse|aes|bmi|fma|popcnt|lzcnt|sha|pclmul' | sort
	@echo "=== GCC Version ==="
	@gcc --version | head -n 1 || true
	@echo "=== GNU Make Header ==="
	@make --version | head -n 1 || true
	@echo "=== Python Version ==="
	@python3 --version || true
	@echo "=== Rust Toolchains ==="
	@rustup show || true
	@echo "=== Jolt VM Toolchain ==="
	@cargo jolt --version 2>/dev/null || echo "Jolt CLI not found"


LINT_LOCS_PY ?= $(shell git ls-files '*.py')

.PHONY: format
format: ##H Format the Rust and Python codebase
	-pre-commit run --all-files
	# Other formatters (python, json, etc)
	-isort $(LINT_LOCS_PY)
	-black $(LINT_LOCS_PY)
	-prettier -w .

.PHONY: lint
lint: ##H Run clippy to lint the codebase and check compilation
	$(CARGO) check
	$(CARGO) clippy --all-targets --all-features -- -D warnings
	@if [ -n "$(VERBOSE)" ]; then \
		echo "Running ZK Security Scanner (vuln-002-VeilCash)"; \
		python3 scripts/detect_vuln_002.py; \
	fi

.PHONY: coverage
coverage: ##H Run workspace code coverage and generate HTML report
	@echo "Running focused workspace code coverage"
	$(CARGO) tarpaulin --out Html \
		--output-dir .tmp/coverage \
		--exclude-files "**/target/*" \
		--ignore-panics \
		--ignore-tests \
		--skip-clean

.PHONY: coverage-lean
coverage-lean: ##H Run focused code coverage for the ruma-lean library
	@echo "Running focused code coverage for ruma-lean"
	$(CARGO) tarpaulin -p ruma-lean --out Html \
		--output-dir .tmp/coverage-lean \
		--exclude-files "src/*" "**/target/*" \
		--ignore-panics \
		--ignore-tests \
		--skip-clean

.PHONY: clean
clean: ##H Clean up cache and optionally build artifacts
	@echo "Cleaning up"
	find . -name .mypy_cache -exec rm -rf {} +;
	find . -name .ruff_cache -exec rm -rf {} +;
	find . -name .pytest_cache -exec rm -rf {} +;
	rm -rf .tmp/coverage .tmp/coverage-lean
# 	$(CARGO) clean


# Clean quotes from variables to avoid "makefile things"
MATRIX_TOKEN := $(subst ",,$(subst ',,$(MATRIX_TOKEN)))
MATRIX_HOMESERVER := $(subst ",,$(subst ',,$(MATRIX_HOMESERVER)))
MATRIX_ROOM_ID := $(subst ",,$(subst ',,$(MATRIX_ROOM_ID)))

export RUST_BACKTRACE ?= 1
export

STYLE_CYAN := \033[36m
STYLE_RESET := \033[0m

# Messes up vim/sublime syntax highlighting, so it's at the end!
.PHONY: help
help: ##H Show this help, list available targets
	@grep -hE '^[a-zA-Z0-9_\/-]+:.*?##H .*$$' $(MAKEFILE_LIST) \
		        | awk 'BEGIN {FS = ":.*?##H "}; {printf "$(STYLE_CYAN)%-20s$(STYLE_RESET) %s\n", $$1, $$2}'
