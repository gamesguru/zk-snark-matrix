# Build tool configuration
SHELL=/bin/bash
.DEFAULT_GOAL=_help

LAKE ?= ~/.elan/bin/lake


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Init and format
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.PHONY: cache
cache: ##H Update Lean cache
	cd ruma-zk-topological-air && $(LAKE) exe cache get


LINT_LOCS_LEAN = $$(git ls-files '**/*.lean')
LINT_LOCS_PY = $$(git ls-files '*.py')
LINT_LOCS_SH = $$(git ls-files '*.sh')

.PHONY: format
format: ##H Format codebase
	-prettier -w .
	-pre-commit run --all-files
	-cargo sort --workspace --grouped
	-black $(LINT_LOCS_PY)
	-isort $(LINT_LOCS_PY)
	-shfmt -w $(LINT_LOCS_SH)

.PHONY: lint
lint: ##H Run clippy across workspace
	cargo clippy --workspace --all-targets --all-features

.PHONY: test
test: ##H Run unit tests and benchmarks
	cargo test --workspace --all-targets --all-features

.PHONY: clean
clean: ##H Remove build artifacts
	-cd ruma-zk-topological-air && $(LAKE) clean
	-cargo clean
	rm -rf target/



# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Main targets
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.PHONY: lean
lean: ##H Run Lean theorem proofs and verification
	cd ruma-zk-topological-air && $(LAKE) build
	@printf "\n${STYLE_GREEN}--- Verification Complete ---${STYLE_RESET}\n"
	@printf "${STYLE_CYAN}Mapped Theorems & Definitions:${STYLE_RESET}\n"
	@grep -E '^(theorem|def|class|instance|structure) ' ruma-zk-topological-air/lean_src/ctopology/*.lean ruma-zk-topological-air/lean_src/ctopology.lean || true
	@printf "${STYLE_GREEN}--------------------------------${STYLE_RESET}\n"

.PHONY: docs
docs: ##H Generate Lean docs
	DOCGEN_SRC="file" DOCGEN_SKIP_LEAN=1 DOCGEN_SKIP_STD=1 DOCGEN_SKIP_LAKE=1 DOCGEN_SKIP_DEPS=1 cd ruma-zk-topological-air && $(LAKE) build ctopology:docs

.PHONY: bench
bench: ##H Run high-performance O(N) benchmark
	cargo run -p ruma-zk-prover --release -- demo

.PHONY: wasm
wasm: ##H Build WebAssembly package (JS + WASM)
	cd ruma-zk-verifier && wasm-pack build --target web -- --features wasm

.PHONY: android
android: ##H Generate Kotlin/Android (UniFFI) bindings
	cargo build -p ruma-zk-verifier
	cargo run -p ruma-zk-verifier --bin uniffi-bindgen generate --library target/debug/libruma_zk_verifier.so --language kotlin --out-dir target/bindings/android

.PHONY: proof-bench
proof-bench: ##H Run topological prover benchmark
	cargo run -p ruma-zk-prover --release -- demo

.PHONY: figures
figures: ##H Generate paper figures
	python3 scripts/crossover_chart.py

.PHONY: paper
paper: ##H Compile paper/paper.tex to PDF
	cd paper && pdflatex -interaction=nonstopmode paper.tex && pdflatex -interaction=nonstopmode paper.tex
	@printf "\n${STYLE_GREEN}--- Paper compiled: paper/paper.pdf ---${STYLE_RESET}\n"



# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Help & support commands
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# [ENUM] Styling / Colors
STYLE_CYAN := $(shell tput setaf 6 2>/dev/null || echo '\033[36m')
STYLE_GREEN := $(shell tput setaf 2 2>/dev/null || echo '\033[32m')
STYLE_RESET := $(shell tput sgr0 2>/dev/null || echo '\033[0m')
export STYLE_CYAN STYLE_GREEN STYLE_RESET

.PHONY: _help
_help:
	@grep -hE '^[a-zA-Z0-9_\/-]+:[[:space:]]*##H .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":[[:space:]]*##H "}; {printf "$(STYLE_CYAN)%-15s$(STYLE_RESET) %s\n", $$1, $$2}'
