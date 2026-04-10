SHELL=/bin/bash

# Variables
CARGO = cargo
PYTHON = python3

# Load environment variables from .env file if it exists
ifneq (,$(wildcard ./.env))
    include .env
endif

# Clean quotes from variables to avoid "makefile things"
MATRIX_TOKEN := $(subst ",,$(subst ',,$(MATRIX_TOKEN)))
MATRIX_HOMESERVER := $(subst ",,$(subst ',,$(MATRIX_HOMESERVER)))
MATRIX_ROOM_ID := $(subst ",,$(subst ',,$(MATRIX_ROOM_ID)))

export RUST_BACKTRACE ?= 1
export

STYLE_CYAN := \033[36m
STYLE_RESET := \033[0m

.DEFAULT_GOAL := help

.PHONY: all
all: build setup format lint test ##H Build, setup data, format, lint, and run tests

.PHONY: build
build: ##H Build the Rust project
	@echo "Building ZK-Matrix-Join..."
	$(CARGO) build

.PHONY: run
run: benchmark

.PHONY: benchmark
benchmark: ##H Run the ZK-Matrix-Join Simulation
	@echo "Running ZK-Matrix-Join Benchmark..."
	$(CARGO) run --release --bin zk-matrix-join-host

.PHONY: benchmark-lite
benchmark-lite: ##H Run Simulation with Tiny 5-Event Graph
	@echo "Running ZK-Matrix-Join Benchmark (Lite)..."
	MATRIX_FIXTURE_PATH=res/ruma_bootstrap_events.json $(CARGO) run --release --bin zk-matrix-join-host

.PHONY: benchmark-batch
benchmark-batch: ##H Run Simulation with Concise DSL Fixtures
	@echo "Running ZK-Matrix-Join Benchmark (Batch DSL)..."
	BATCH_FIXTURE=demo $(CARGO) run --release --bin zk-matrix-join-host

.PHONY: prove
prove: ##H Generate full Jolt STARK Proof
	@echo "Generating Jolt STARK Proof..."
	JOLT_PROVE=1 RUST_LOG=info $(CARGO) run --release --bin zk-matrix-join-host

.PHONY: test
test: ##H Run fast Native Resolution tests (<1s)
	@echo "Running Fast Native Tests..."
	$(CARGO) test -p zk-matrix-join-host -- --nocapture

.PHONY: test-zk
test-zk: ##H Run the full Jolt Parity Simulation
	@echo "Running Deep Jolt Parity Simulation..."
	RUST_LOG=info RAYON_NUM_THREADS=1 $(CARGO) test --release -p zk-matrix-join-host -- --ignored --nocapture --test-threads=1

.PHONY: setup
setup: ##H Combined: Fetch real Matrix data and Ruma state resolution fixtures
	@echo "Setting up project data and fixtures..."
	@if [ -n "$$MATRIX_TOKEN" ]; then \
		echo "Fetching real Matrix state data from $$MATRIX_HOMESERVER..."; \
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
	@echo "Running ZK Security Scanner (vuln-002-VeilCash)..."
	python3 scripts/detect_vuln_002.py

.PHONY: coverage
coverage: ##H Run workspace code coverage and generate HTML report
	@echo "Running focused workspace code coverage..."
	$(CARGO) tarpaulin --out Html \
		--output-dir .tmp/coverage \
		--exclude-files "**/target/*" \
		--ignore-panics \
		--ignore-tests \
		--skip-clean

.PHONY: coverage-lean
coverage-lean: ##H Run focused code coverage for the ruma-lean library
	@echo "Running focused code coverage for ruma-lean..."
	$(CARGO) tarpaulin -p ruma-lean --out Html \
		--output-dir .tmp/coverage-lean \
		--exclude-files "src/*" "**/target/*" \
		--ignore-panics \
		--ignore-tests \
		--skip-clean
.PHONY: clean
clean: ##H Clean up cache and optionally build artifacts
	@echo "Cleaning up..."
	find . -name .mypy_cache -exec rm -rf {} +;
	find . -name .ruff_cache -exec rm -rf {} +;
	find . -name .pytest_cache -exec rm -rf {} +;
	rm -rf .tmp/coverage .tmp/coverage-lean
# 	$(CARGO) clean


# Messes up vim/sublime syntax highlighting, so it's at the end!
.PHONY: help
help: ##H Show this help, list available targets
	@grep -hE '^[a-zA-Z0-9_\/-]+:.*?##H .*$$' $(MAKEFILE_LIST) \
		        | awk 'BEGIN {FS = ":.*?##H "}; {printf "$(STYLE_CYAN)%%-20s$(STYLE_RESET) %%s\n", $$1, $$2}'
