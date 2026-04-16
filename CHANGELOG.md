# Changelog

All notable public releases should be summarized here.

## Unreleased

## [v0.1.1]

- Add the new `hasp setup` flow for first-run machine, repo, and agent MCP configuration.
- Expand bootstrap, doctor, and operator guidance so local install and setup are easier to verify end to end.
- Harden the packaged release lifecycle with verify, install, upgrade, uninstall, hosted artifact publication, and Homebrew tap updates.
- Improve test and coverage rigor, including deterministic `100.0%` coverage and a stable default `go test ./...` path in test binaries.

## [v0.1.0]

- Initial public export and release-publication lane setup.
- Public release workflow for GitHub Releases, Cloudflare R2 mirroring, and Homebrew tap publication.
- Signed packaged releases with verification material and artifact-pinned formula generation.
