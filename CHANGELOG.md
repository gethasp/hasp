# Changelog

All notable public releases should be summarized here.

## Unreleased

## [v0.1.6]

- Shift `hasp setup` to a machine-wide onboarding model with defaults for automatic project adoption on first use.
- Auto-create local project bindings from machine defaults when HASP is first used in a project, instead of requiring manual per-repo setup.
- Keep repo-scoped enforcement under the hood while removing the repo-by-repo onboarding tax.
- Maintain the corrected repo coverage gate at `100.0%`.

## [v0.1.5]

- When interactive `hasp setup` master password confirmation does not match, setup now retries the password step in place instead of aborting the whole flow.
- Keep the retry path fully covered while preserving the corrected `100.0%` repo coverage gate.

## [v0.1.4]

- Ignore saved setup defaults that point into ephemeral temp directories, so stale test or temp paths no longer show up as the default local HASP data directory.
- Tighten the `hasp setup` terminal layout with clearer visual stage separators and more compact guidance lines.
- Keep the redesigned setup flow fully covered and the corrected repo coverage gate at `100.0%`.

## [v0.1.3]

- Replace the freeform interactive agent prompt in `hasp setup` with a numbered agent selection menu.
- Add a final review-and-confirm screen before `hasp setup` writes local vault, repo, or agent config changes.
- Keep interactive setup human-readable while preserving `--json` and non-interactive automation paths.
- Maintain a stable default `go test ./...` path and a corrected `100.0%` coverage gate after the setup redesign.

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
