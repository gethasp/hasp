# Scripts

This directory contains helper scripts that are part of the public CLI/broker
repo. A script belongs here only when it can run from this checkout and supports
one of these jobs:

- build or test the Go module
- install local repo guardrails
- package, sign, verify, or install releases
- publish prepared release artifacts
- check public docs and release metadata

If a helper needs files outside this checkout, it should stay out of this
directory.

## Build and checks

- `build.sh`: builds `bin/hasp`.
- `bootstrap_go_tools.sh`: installs or verifies Go analysis tools.
- `check-go-mod-tidy.sh`: verifies `apps/server/go.mod` and `go.sum`.
- `check-markdown-links.sh`: checks links in public Markdown files.
- `conformance.sh`: runs the release-blocking conformance lane.
- `run-go-tests.sh`: runs Go tests with the fast test KDF tag.
- `run-go-analysis.sh`: runs lint, staticcheck, and vulncheck profiles.
- `run-go-coverage.sh`: generates coverage output.
- `run-go-benchmarks.sh`: runs benchmark suites.
- `run-go-evals.sh`: runs end-to-end evals.
- `release-smoke.sh`: smoke-tests packaged release artifacts.

## Repo guardrails

- `hasp-install-hooks.sh`: installs HASP git hooks in the current repo.
- `hasp-pre-commit.sh`: pre-commit hook entry point.
- `hasp-pre-push.sh`: pre-push hook entry point.
- `hasp-common.sh`: shared hook helpers.
- `hasp-deploy.sh`: deploy guardrail entry point.

## Release packaging and verification

- `package-release.sh`: builds one release tarball for the current target.
- `package-public-release.sh`: builds the multi-target release directory.
- `assemble-public-release.sh`: assembles checksums, metadata, and formula input.
- `generate-supply-chain-artifacts.sh`: emits release provenance material.
- `hasp-release-common.sh`: shared release helper functions.
- `hasp-sign-release.sh`: signs a prepared release artifact.
- `hasp-verify-release.sh`: verifies a release tarball and sidecars.
- `hasp-install-release.sh`: installs a verified release tarball.
- `hasp-upgrade-release.sh`: upgrades an installed release.
- `hasp-uninstall-release.sh`: removes an installed release tree.
- `render-homebrew-formula.sh`: renders the Homebrew formula from metadata.
- `release-notes-from-changelog.sh`: extracts release notes from the changelog.

## Publication

- `publish-release-to-r2.sh`: mirrors a prepared release directory to R2.
- `publish-r2-release.sh`: compatibility wrapper for R2 publication.
- `publish-homebrew-tap.sh`: copies the rendered CLI formula into a tap checkout.

Publication scripts require explicit credentials and target paths from the
operator environment. They should fail when required inputs are missing.

## Script tests

- `test-check-go-mod-tidy.sh`: regression coverage for the tidy checker.

Run the default script test with:

```bash
make test-scripts
```
