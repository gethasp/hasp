# Changelog

All notable public releases should be summarized here.

## Unreleased

## [v0.1.2]

- Redesign `hasp setup` into a more contextual staged onboarding flow with clearer machine, repo, and agent guidance.
- Stop stale saved setup paths from surfacing dead temp directories as the default local HASP data path.
- Keep interactive setup human-readable while preserving `--json` and non-interactive machine output for automation.
- Stabilize the default parallel Go test path while keeping the corrected coverage gate at `100.0%`.

## [v0.1.1]

- Add the new `hasp setup` flow for first-run machine, repo, and agent MCP configuration.
- Expand bootstrap, doctor, and operator guidance so local install and setup are easier to verify end to end.
- Harden the packaged release lifecycle with verify, install, upgrade, uninstall, hosted artifact publication, and Homebrew tap updates.
- Improve test and coverage rigor, including deterministic `100.0%` coverage and a stable default `go test ./...` path in test binaries.

## [v0.1.0]

- Initial public export and release-publication lane setup.
- Public release workflow for GitHub Releases, Cloudflare R2 mirroring, and Homebrew tap publication.
- Signed packaged releases with verification material and artifact-pinned formula generation.
