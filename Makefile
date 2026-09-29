SHELL := /bin/bash
PY := ./.venv/bin/python
export PATH := $(HOME)/.foundry/bin:$(CURDIR)/.venv/bin:$(PATH)

TASK ?= benchmark/tasks/reentrancy/task_001
GEN  ?= fixture

.PHONY: help setup demo bench run echidna test test-int lint versions clean

help:
	@echo "make setup     - install toolchain (venv, Foundry, solc, Slither, Echidna) + versions.lock"
	@echo "make demo      - run the bundled reentrancy task end-to-end (offline, fixture generator)"
	@echo "make bench     - run all strategies across all tasks -> RQ confusion matrix + Pareto"
	@echo "make run       - run a task: make run TASK=<dir> GEN=fixture|replay"
	@echo "make echidna   - run a task's Echidna invariant (independent property oracle)"
	@echo "make test      - fast offline unit tests"
	@echo "make test-int  - integration tests (real Foundry + Slither + Echidna)"
	@echo "make lint      - ruff"
	@echo "make versions  - print resolved tool versions"
	@echo "make clean     - remove run artifacts and caches"

setup:
	bash scripts/bootstrap.sh

demo:
	$(PY) -m falsify.cli demo

bench:
	$(PY) -m falsify.cli bench

run:
	$(PY) -m falsify.cli run --task $(TASK) --generator $(GEN)

echidna:
	$(PY) -m falsify.cli echidna --all

test:
	$(PY) -m pytest -q -m "not integration"

test-int:
	$(PY) -m pytest -q -m integration

lint:
	$(PY) -m ruff check falsify tests

versions:
	$(PY) -c "from falsify import versions; import dataclasses,json; print(json.dumps(dataclasses.asdict(versions.capture()), indent=2))"

clean:
	rm -f results/*.json
	rm -rf .pytest_cache .ruff_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
