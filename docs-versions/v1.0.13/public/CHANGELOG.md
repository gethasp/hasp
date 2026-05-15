# Changelog

All notable public releases should be summarized here.

## Unreleased

## [v1.0.13]

- Keep public release evals aligned with the setup convenience-unlock hardening
  so merge-gate CI covers the new macOS Keychain failure contract.

## [v1.0.12]

- Make setup keychain failures explicit: convenience-unlock errors now say the
  macOS login keychain rejected access, not the HASP master password.
- Show `Setup complete with warnings` when setup succeeds but convenience
  unlock is unavailable.
- Treat `--enable-convenience-unlock=always` as a hard setup contract so setup
  cannot report success while leaving the requested unlock path unusable.

## [v1.0.11]

- Made the public installer regression test portable to clean Linux runners by
  accepting the expected "install directory is not on PATH" warning while
  preserving the dedicated stale-`hasp` shadowing assertion.
- Continue the 100% server coverage release line after the v1.0.10 public CI
  attempt exposed the Linux-only installer-test assumption.

## [v1.0.10]

- Split public script-test execution into named release and merge-gate steps so
  Linux CI identifies the exact script regression instead of reporting the
  aggregate `test-scripts` lane.
- Continue the 100% server coverage release line with a small release-version
  parser regression test.

## [v1.0.9]

- Split the public `verify-ci` aggregate into named workflow steps for release
  and merge gates so Linux CI reports whether links, generated docs, workflow
  lint, shellcheck, web checks, server tests, or server lint failed.
- Carry forward the 100% server coverage gate and release diagnostic hardening
  from the v1.0.7 and v1.0.8 release attempts.

## [v1.0.8]

- Move public non-secret release preflight and merge-gate checks to
  GitHub-hosted Linux and split the release gates into named steps so CI
  failures identify the exact failing lane instead of collapsing into one
  opaque `make release-gate` or `make release-preflight` result.
- Preserve the 100% server coverage release gate and the v1.0.7 MCP/coverage
  hardening in the release line.

## [v1.0.7]

- Raise the server release coverage gate to 100% with regression coverage
  across runtime HTTP/RPC paths, app command errors, HTTP auth/HMAC handling,
  integrations, store backup/config/policy paths, telemetry, leases,
  approvals, and support utilities.
- Simplify unreachable defensive branches surfaced by the coverage push while
  preserving production error handling for reachable failure modes.

## [v1.0.6]

- Harden managed agent MCP startup so initialization and tool discovery stay
  available even when vault unlock, saved consumer lookup, session setup, or
  process registration preflight fails.
- Contain vault unlock failures during MCP tool execution as JSON-RPC tool
  errors instead of process exits.
- Isolate HTTP vault-init regression coverage from the operator macOS Keychain.

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
