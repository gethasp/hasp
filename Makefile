.PHONY: build build-debug build-min-size check-links check-tidy test-scripts test test-integration test-race evals coverage benchmarks benchmark-smoke lint staticcheck vulncheck lint-full verify-ci verify conformance release-smoke package-release package-public-release publish-r2 publish-tap install-hooks help

VERSION ?= $(shell cat VERSION 2>/dev/null || echo 0.0.0-dev)

## build: Build the local HASP broker binary
build:
	@bash ./scripts/build.sh

## build-debug: Build an unstripped debug binary
build-debug:
	@bash ./scripts/build.sh --debug

## build-min-size: Build the smallest local binary variant
build-min-size:
	@bash ./scripts/build.sh --min-size

## check-links: Verify Markdown links
check-links:
	@bash ./scripts/check-markdown-links.sh

## check-tidy: Verify go.mod/go.sum tidiness
check-tidy:
	@bash ./scripts/check-go-mod-tidy.sh

## test-scripts: Run regression coverage for exported repo verification scripts
test-scripts:
	@bash ./scripts/test-check-go-mod-tidy.sh

## test: Run the fast local verification path
test:
	@bash ./scripts/run-go-tests.sh

## test-integration: Run integration-tagged tests
test-integration:
	@bash ./scripts/run-go-tests.sh --integration

## test-race: Run the race detector
test-race:
	@bash ./scripts/run-go-tests.sh --race

## evals: Run end-to-end system evals
evals:
	@bash ./scripts/run-go-evals.sh

## coverage: Generate a Go coverage summary
coverage:
	@bash ./scripts/run-go-coverage.sh

## benchmarks: Run benchmark suites
benchmarks:
	@bash ./scripts/run-go-benchmarks.sh

## benchmark-smoke: Run lightweight benchmark smoke coverage
benchmark-smoke:
	@bash ./scripts/run-go-benchmarks.sh --smoke

## lint: Run vet + golangci-lint
lint:
	@bash ./scripts/run-go-analysis.sh --profile lint

## staticcheck: Run staticcheck directly
staticcheck:
	@bash ./scripts/run-go-analysis.sh --profile staticcheck

## vulncheck: Run govulncheck
vulncheck:
	@bash ./scripts/run-go-analysis.sh --profile vulncheck

## lint-full: Lint plus vulncheck
lint-full: lint vulncheck

## verify-ci: Canonical fast CI gate
verify-ci: check-links check-tidy test-scripts test lint

## verify: Default public verification gate
verify: verify-ci release-smoke coverage vulncheck

## conformance: Run the release-blocking conformance lane
conformance:
	@bash ./scripts/conformance.sh

## release-smoke: Run packaged-binary smoke checks
release-smoke:
	@bash ./scripts/release-smoke.sh

## package-release: Build a single-target distributable release tarball
package-release:
	@bash ./scripts/package-release.sh

## package-public-release: Build the multi-target public release set
package-public-release:
	@bash ./scripts/package-public-release.sh v$(VERSION)

## publish-r2: Upload the prepared public release set to Cloudflare R2
publish-r2:
	@bash ./scripts/publish-release-to-r2.sh dist/public-release/v$(VERSION) v$(VERSION)

## publish-tap: Copy the rendered formula into a tap checkout
publish-tap:
	@bash ./scripts/publish-homebrew-tap.sh $(PUSH) dist/public-release/v$(VERSION)/Formula/hasp.rb $(TAP_REPO) v$(VERSION)

## install-hooks: Install the repo guardrail hooks into the current repo
install-hooks:
	@bash ./scripts/hasp-install-hooks.sh

## help: Show this help
help:
	@grep -E '^## ' Makefile | sed 's/## //' | column -t -s ':'
