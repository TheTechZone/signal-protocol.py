SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
# .DELETE_ON_ERROR:
MAKEFLAGS = --warn-undefined-variables
MAKEFLAGS += --no-builtin-rules

# Override PWD so that it's always based on the location of the file and **NOT**
# based on where the shell is when calling `make`. This is useful if `make`
# is called like `make -C <some path>`
PWD := $(realpath $(dir $(abspath $(firstword $(MAKEFILE_LIST)))))

WORKTREE_ROOT := $(shell git rev-parse --show-toplevel 2> /dev/null)
RUST_TOOLCHAIN := $(shell cat rust-toolchain)

# Using $$() instead of $(shell) to run evaluation only when it's accessed
# https://unix.stackexchange.com/a/687206
py = $$(if [ -d $(PWD)/'.venv' ]; then echo $(PWD)/".venv/bin/python3"; else echo "python3"; fi)
pip = $(py) -m pip

.PHONY:
setup: ## Setup for development
	curl https://sh.rustup.rs -sSf | sh -s -- --default-toolchain $(RUST_TOOLCHAIN) -y
	make venv

.PHONY:
venv: requirements.txt  ## Build the virtual environment
	$(py) -m venv .venv
	$(pip) install -U -r requirements.txt
	touch .venv

.PHONY:
lint: ## Fix style issues
	. .venv/bin/activate && black .
	cargo fmt

.PHONY:
dev: ## Build the library (dev mode)
	. .venv/bin/activate && maturin develop

.PHONY:
build: ## Build wheels (both source and binary)
	. .venv/bin/activate && maturin build --release

.PHONY:
test: ## Run the Python test suite
	. .venv/bin/activate && pytest -v tests/

.PHONY:
stubs: ## Sync python stubs files with the rust codebase - in particular docstrings
	. .venv/bin/activate && python3 script/fix-docstrings.py && black signal_protocol/*.pyi

.PHONY:
check-rust: ## Run Rust checks (clippy, fmt)
	cargo fmt -- --check
	cargo clippy -- -D warnings

.PHONY:
check-python: ## Run Python checks (black, mypy)
	. .venv/bin/activate && black --check .
	. .venv/bin/activate && mypy signal_protocol

.PHONY:
check: check-rust check-python ## Run all code quality checks

.PHONY:
clean: ## Clean build artifacts
	cargo clean
	rm -rf target/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	find . -type d -name "__pycache__" -exec rm -rf {} +

.PHONY:
wheels: ## Build wheels for all supported Python versions using Docker
	docker run --rm -v $(PWD):/io ghcr.io/pyo3/maturin build --release --strip

.PHONY:
help: ## Display this help
	@awk 'BEGIN {FS = ":.*##"; printf "Usage:\n  make \033[36m<target>\033[0m\n\nTargets:\n"} /^[a-zA-Z0-9_-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

.DEFAULT_GOAL := help
