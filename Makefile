.PHONY: build build-debug build-min-size check-links check-tidy check-generated-docs workflow-lint shellcheck test-scripts test-release-publication test test-integration test-race evals coverage coverage-audit-platform benchmarks benchmark-smoke lint staticcheck vulncheck lint-full web-check verify-ci verify release-gate conformance release-smoke package-release package-public-release publish-r2 publish-tap install-hooks help

REPO_ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
VERSION ?= $(shell cat VERSION 2>/dev/null || echo 0.0.0-dev)
TOOLS_BIN := $(REPO_ROOT)/bin/tools

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

## check-generated-docs: Verify generated docs match the current binary help
check-generated-docs:
	@bash ./scripts/check-generated-docs.sh

## workflow-lint: Validate GitHub Actions workflows
workflow-lint:
	@PATH="$(TOOLS_BIN):$$PATH" actionlint -shellcheck= -config-file .github/actionlint.yaml .github/workflows/*.yml
	@bash ./scripts/check-github-actions-pinning.sh .github/workflows

## shellcheck: Run shellcheck over release and maintenance scripts
shellcheck:
	@find scripts -type f -name '*.sh' -print0 | xargs -0 shellcheck -x -P scripts

## test-scripts: Run regression coverage for exported repo verification scripts
test-scripts:
	@bash ./scripts/run-public-script-tests.sh

## test-release-publication: Run heavyweight release-publication regression coverage
test-release-publication:
	@bash ./scripts/test-release-publication.sh

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

## coverage-audit-platform: Prove audit file-state coverage on the current GOOS
coverage-audit-platform:
	@HASP_COVERAGE_TARGET=100 bash ./scripts/run-audit-platform-coverage.sh

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

## web-check: Validate exported web and download Worker surfaces
web-check:
	@if command -v corepack >/dev/null 2>&1; then corepack enable && corepack prepare pnpm@10.33.2 --activate; fi
	@pnpm -C apps/web install --frozen-lockfile
	@$(MAKE) -C apps/web check
	@python3 ./scripts/check-public-docs-versioning.py

## verify-ci: Canonical fast CI gate
verify-ci: check-links check-tidy check-generated-docs workflow-lint shellcheck test-scripts web-check test lint

## verify: Default public verification gate
verify: verify-ci release-smoke coverage vulncheck

## release-gate: Release-blocking gate with all tests and 100% Go coverage
release-gate:
	@$(MAKE) verify-ci
	@$(MAKE) test-release-publication
	@$(MAKE) evals
	@$(MAKE) vulncheck
	@$(MAKE) test-integration
	@$(MAKE) test-race
	@HASP_COVERAGE_TARGET=100 $(MAKE) coverage
	@$(MAKE) conformance

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
