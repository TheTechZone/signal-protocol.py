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
	. .venv/bin/activate && SETUPTOOLS_ENABLE_FEATURES="legacy-editable" python -m pip install --editable .

.PHONY:
build: ## Build wheels (both source and binary)
	. .venv/bin/activate && python -m build

.PHONY:
test: ## Run the Python test suite
	. .venv/bin/activate && pytest -v tests/

.PHONY:
clean: ## Clean up
	@[ -d ./.pytest_cache ] && rm -rf .pytest_cache || true
	@[ -d ./signal_protocol.egg-info ] && rm -rf ./signal_protocol.egg-info || true
	@[ -d ./build ] && rm -rf build || true
	@[ -d ./dist ] && rm -rf dist || true
	@[ -d ./target ] && rm -rf target || true
	@[ -d ./tests/__pycache__ ] && rm -rf ./tests/__pycache__ || true

.DEFAULT_GOAL := help
.PHONY: help
help: ## Display this help section
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z\$$/]+.*:.*?##\s/ {printf "\033[36m%-38s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
