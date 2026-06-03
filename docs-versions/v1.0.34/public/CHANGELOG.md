# Changelog

All notable public releases should be summarized here.

## Unreleased

## [v1.0.34]

- Prevent managed Claude Code and Codex CLI MCP wrappers from being pinned to
  stale `HASP_AGENT_HASP` binaries, and make the release gate fail when
  generated MCP configs or wrapper ordering could shadow the managed binary.
- Make `hasp_run` release-gate coverage execute through a managed wrapper with
  a deliberately stale inherited `HASP_SESSION_TOKEN`, proving MCP session
  recovery before a tag ships.
- Teach `hasp doctor` and the MCP release gate to detect already-running stale
  agent MCP bridge processes, report exact PIDs, and tell operators to restart
  the affected agent session instead of retrying a dead MCP connection.

## [v1.0.33]

- Recover MCP tool calls from stale inherited `HASP_SESSION_TOKEN` values,
  including sessions that no longer exist or point at a different project.
- Keep explicit MCP `session_token` values fail-closed while returning a clear
  diagnostic that tells agents to omit stale explicit tokens and let HASP open a
  fresh local MCP session.
- Restore release-blocking 100% Go statement coverage after the MCP hardening
  work and refresh the public export mirror.
- Raise Go modules to 1.26.4 to clear current Go stdlib OSV advisories before
  release.

## [v1.0.32]

- Ship credential sets in value-free manifests, including schema validation for
  `google_oauth_client`, set-role target delivery through `from_set` and
  `role`, project command output, MCP target metadata, brokered execution, and
  regression coverage.

## [v1.0.31]

- Document the scoped credential-set model for coupled credentials such as
  Google OAuth client IDs and client secrets, including the interim value-free
  manifest pattern to use before credential sets ship.
- Restore and verify the source 100% coverage gate after the manifest-target
  hardening work by adding focused coverage and removing unreachable branches.

## [v1.0.30]

- Add value-free repo manifest target authoring and review commands through
  `hasp project target ...` and the `hasp template ...` alias, so agents can
  request brokered workflows without storing raw secret values in the repo.
- Require local target review before `hasp run --target`,
  `hasp inject --target`, `hasp write-env --target`, MCP target execution, or
  `hasp app connect --target` can authorize refs or seed runtime profiles.
- Improve project binding diagnostics so `hasp doctor`, manifest-backed
  secret flows, and `hasp secret add --expose` distinguish unbound repos from
  bindings that point at missing vault items.

## [v1.0.29]

- Add `hasp audit recover` so operators can archive a degraded audit log,
  emit a recovery report, and start a fresh tamper-evident chain without
  rewriting historical entries.
- Document the degraded audit-log recovery workflow in the quickstart and
  generated CLI reference.

## [v1.0.28]

- Distinguish missing named references from existing vault items that are not
  exposed to the current project, with specific CLI and MCP recovery metadata.
- Keep default MCP secret tooling safe-by-default while documenting the explicit
  operator path for exposing existing vault items to a repo.
- Add release-blocking web dependency audit coverage and patch the vulnerable
  `ws` transitives in the private docs toolchain.
- Rotate download Worker release pins through secrets by default, avoiding
  route-aware Worker deploys unless explicitly requested.

## [v1.0.27]

- Accept trailing known flags across the remaining `hasp secret` subcommands,
  including `hasp secret add NAME --from-stdin --expose=never --json`.
- Track the next surgical release-hardening work for vulnerable web-toolchain
  transitives, package-manager audit gates, and Node deprecation warnings.

## [v1.0.26]

- Prevent `hasp secret expose NAME --project-root <repo> --json` from
  partially succeeding and then returning a false `E_NOT_FOUND` by parsing
  trailing command flags before secret-name mutation.
- Add regression coverage for agent-style secret exposure commands where flags
  follow the named secret.
- Track the next surgical hardening work for secret-command flag parsing,
  unexposed named-reference diagnostics, and MCP project-exposure metadata.

## [v1.0.25]

- Restore brokered Claude Code and Codex CLI secret delivery for ad-hoc macOS
  CLI installs by falling back to the local daemon HMAC file when the running
  binary does not match app-bundle signing requirements.
- Prevent future audit sequence collisions by serializing audit appends across
  independent CLI and MCP processes.
- Keep MCP sessions project-bound for existing rootless agent records by
  resolving the repo from `HASP_AGENT_PROJECT_ROOT` or the agent process
  working directory.

## [v1.0.24]

- Use the release-build bootstrap profile for the macOS public artifact build
  job so release publication does not depend on Linux verification tooling.

## [v1.0.23]

- Repair the public release workflow for Darwin-native daemon HMAC keychain
  artifacts by building the full public release set on macOS.
- Keep Linux public preflight focused on static package-contract checks when
  Darwin CGO artifacts cannot be built on that runner.

## [v1.0.22]

- Make Claude Code and Codex CLI MCP startup survive slow daemon initialization
  by waiting for readiness before the agent MCP handshake proceeds.
- Add a release-blocking MCP gate that verifies bare MCP startup, Claude/Codex
  managed wrappers, generated MCP config, and tool listing before release
  artifacts can ship.
- Block Darwin release artifacts that contain stubbed daemon HMAC keychain
  support, preventing packages built with test fast-KDF/no-cgo paths from
  breaking brokered secret delivery.

## [v1.0.21]

- Add Pi as a first-class brokered agent profile with setup support, generated
  local package bridging, profile metadata, docs, release gates, and public
  mirror coverage.
- Restore basic terminal interrupt behavior during interactive `hasp setup` so
  the first Ctrl-C terminates setup instead of being swallowed by context
  cancellation.
- Harden release verification around stale download Worker metadata so live
  release checks report the pinned Worker version precisely.

## [v1.0.20]

- Restore and verify the server 100% coverage gate across app setup, MCP
  authorization, broker operations, project context, HTTP helpers, runtime
  process identity, store grants, and telemetry payload tooling.
- Keep the exported public mirror aligned with the private source coverage
  suite, including the new coverage-focused regression tests.
- Fix a runtime backup scheduler race-test hazard by making test scheduler
  timing instance-local instead of mutating shared package state.

## [v1.0.19]

- Close the May 16 security review backlog with broker authorization
  hardening, public Worker ingress controls, dependency and OSV gates, static
  docs XSS containment, public recon drift tracking, and release verification
  coverage.
- Add structured authorization requirements for broker grant actions and share
  brokered run/inject execution across CLI and MCP while keeping `write-env`
  as a separate workspace-visible export path.
- Harden macOS HTTP signing to fail closed on randomness failures and extend
  the signer contract tests.

## [v1.0.18]

- Make public release gates prove the live first-party telemetry endpoint by
  generating the probe body from the core CLI telemetry encoder, then checking
  DNS, TLS SNI, and the `/v1/cli/ping` response contract before release.

## [v1.0.17]

- Ship the process-identity authorization hardening with deterministic Darwin
  race-test coverage after the v1.0.16 public release workflow stopped before
  publishing artifacts.

## [v1.0.16]

- Harden process-bound session resolution so daemon RPC callers can only
  resolve sessions for their kernel-attested socket peer PID.
- Disable implicit process binding when the platform cannot provide a
  per-process stale-binding token instead of falling back to PID ancestry.
- Replace shell-based process ancestry checks with native platform lookups and
  refuse daemon stop when a pidfile does not match the live HASP daemon socket.

## [v1.0.15]

- Harden the public release workflow against transient macOS arm64 race-test
  runner failures by retrying the Darwin race step once before failing.

## [v1.0.14]

- Make the setup convenience-unlock eval platform-aware so Linux CI verifies
  the disabled path while macOS verifies best-effort Keychain unavailability.

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
