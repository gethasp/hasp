# Changelog

All notable public releases should be summarized here.

## Unreleased

## [v1.0.5]

- Add optional HASP CLI telemetry with explicit setup consent, `hasp telemetry`
  controls, a first-party ingest endpoint, strict payload allowlists, and
  default-off/no-network behavior unless the user opts in.

## [v1.0.4]

- Harden the private-to-public release driver so live verification waits for
  the Homebrew tap publish to land before fetching or installing from the tap.
- Add release-publication regression coverage for the live verifier's
  Homebrew polling path.

## [v1.0.3]

- Fix the public Release workflow so pre-publish release smoke no longer tries
  to install the Homebrew formula before the new artifacts are available on the
  R2 mirror.
- Keep Homebrew install verification after R2 publication and before Homebrew
  tap publication, then verify the published tap before creating the GitHub
  Release.

## [v1.0.2]

- Harden managed agent MCP startup so stale wrappers still answer the MCP
  initialize handshake instead of exiting when a saved agent record is missing.
- Make `hasp setup --agent <id>` persist the matching agent consumer record for
  every supported harness, including Codex CLI, Claude Code, Cursor, Aider,
  Hermes, and OpenClaw.
- Add regression coverage for every managed agent harness from setup through
  wrapper generation, persisted consumer state, and `hasp agent mcp` tools
  listing.

## [v1.0.1]

- Fix macOS setup convenience unlock so normal Keychain prompt latency does not
  get reported as an unavailable keychain.
- Fix `hasp proof --secret <alias>` so project aliases such as `secret_01`
  resolve correctly during brokered proof checks.
- Keep the public installer compatible with the published v1 release archive
  layout.

## [v1.0.0]

- Publish HASP v1 as the first public code and documentation line.
- Ship the local-first runtime secret broker with encrypted vault storage,
  project-scoped bindings, repo guardrails, protected agent process-tree
  sessions, one-time plaintext approval grants, brokered command execution,
  audited secret use, value-free repo manifests, and first-class agent profiles.
- Publish the release through the public Release workflow: supported-platform
  tarballs, checksums, detached GPG signatures, packaged SBOM/provenance/status
  sidecars, Ed25519 upgrade signatures, Cloudflare R2 mirrors, download Worker
  metadata, Homebrew tap publication, and GitHub Release assets.
- Start public versioned documentation at `/docs/v1.0.0/`; the private source
  repository keeps pre-v1 development history and archived release notes.
