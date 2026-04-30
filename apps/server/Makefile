.PHONY: build build-debug build-min-size test test-integration test-race evals coverage benchmarks benchmark-smoke lint staticcheck vulncheck modelcheck-setup

REPO_ROOT := $(shell git rev-parse --show-toplevel 2>/dev/null || pwd)

build:
	@bash ../../scripts/build.sh

build-debug:
	@bash ../../scripts/build.sh --debug

build-min-size:
	@bash ../../scripts/build.sh --min-size

test:
	@bash ../../scripts/run-go-tests.sh

test-integration:
	@bash ../../scripts/run-go-tests.sh --integration

evals:
	@bash ../../scripts/run-go-evals.sh

coverage:
	@bash ../../scripts/run-go-coverage.sh

benchmarks:
	@bash ../../scripts/run-go-benchmarks.sh

benchmark-smoke:
	@bash ../../scripts/run-go-benchmarks.sh --smoke

test-race:
	@bash ../../scripts/run-go-tests.sh --race

lint:
	@bash ../../scripts/run-go-analysis.sh --profile lint

staticcheck:
	@bash ../../scripts/run-go-analysis.sh --profile staticcheck

vulncheck:
	@bash ../../scripts/run-go-analysis.sh --profile vulncheck

modelcheck-setup:
	@bash ../../scripts/modelcheck-setup.sh
