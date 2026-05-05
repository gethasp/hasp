# Changelog

All notable public releases should be summarized here.

## Unreleased

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
