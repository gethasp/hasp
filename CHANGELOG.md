# Changelog

All notable public releases should be summarized here.

## Unreleased

## [v0.1.34]

- Fix the public release CI lane: add `TestMain` HASP_HOME defaults to `apps/server/cmd/hasp` and `apps/server/internal/runner` so the `paths.Resolve` test-isolation guard does not fire on packages that previously relied on a real `~/.hasp` fallback.
- Make the canonical-root cache invalidation test deterministic on Linux tmpfs by replacing `RemoveAll`+`Mkdir` (which can reuse the same inode immediately) with a sibling-create plus rename, guaranteeing a distinct inode for `os.SameFile`.
- Stabilize two CI-only flakes: poll for the daemon pid file (not just the socket) before `StopDaemon` in `TestDaemonCommandStartBranch`, and widen the GrantOnce TTL in `TestEnforceSecretPlaintextPolicyConsumeFailure` so the assertion remains focused on the persist-failure path under heavy CI load.
- Fix a Linux-only PTY drain race in `executePTY` where fast-exit children like `printf hello-pty` could lose their final bytes: wait for the master→stdout io.Copy goroutine to finish (slave-close naturally surfaces buffered data plus EIO on the master) before force-closing `ptmx`, with a 100ms timeout fallback so detached grandchildren that kept the slave fd open cannot stall the runner.
- Widen the four remaining 2-second `daemon shutdown` safety caps in test helpers (`internal/mcp`, `internal/brokerops`, `internal/runtime`, plus the second `internal/app` helper) to 10 seconds so a slow scheduler tick during the public release coverage lane no longer fails an otherwise-clean test cleanup.
- Fix a daemon-readiness race in the `internal/evals` integration helpers: after the v0.1.33 change that made `hasp status` connect-only, the helpers were switched to `hasp daemon start`, but `StartDaemon` returns as soon as the broker is spawned (before the Unix socket is bound), so `TestCLISessionLifecycleEval` and `TestStopEvalDaemonStopsDetachedDaemon` could race the dial. Add a `waitForEvalSocket` poll (15s deadline, 25ms tick) immediately after each `daemon start` so dependent dials see a ready broker. Also add the `--grant-window 15m` flag to `run`, `inject`, `capture`, and `write-env` invocations in `TestCLIEndToEndMatrix`, since the v0.1.33 hardening pass made an explicit window duration mandatory whenever any `--grant-*` scope is `window`.

## [v0.1.33]

- Land the P0 security hardening pass: peer-UID check on the daemon Unix socket, crash-safe vault envelope writes, encoding-aware byte-range redactor, refusal of argv-delivered plaintext in secret commands, write-env clobber protection, scrubbing of inherited HASP env in spawned children, hardened git shell-outs, per-session inject directories, normalized vault unwrap errors, removal of the `.test-basename` KDF weakening seam, and HMAC-chained audit log entries under a per-vault key.
- Migrate the vault KDF to argon2id with a backwards-compatible read path, ship `hasp vault rekdf` to upgrade existing vaults in place, and add `hasp vault forget-device` plus a wider `hasp vault lock` surface.
- Add operator-facing CLI verbs: `hasp secret show / reveal / copy`, `hasp secret search`, `hasp secret diff`, `hasp session list --mine --json`, `hasp audit tail [-n N] [-f]`, `hasp completion <bash|zsh|fish|powershell>`, and inline TTY confirm for agent-safe plaintext reveal/copy.
- Stabilize the user surface: enforce a strict `--json` contract with structured error envelopes, introduce stable error codes and exit-code buckets, standardise `--env NAME=@REF` grammar across `run` / `write-env` / `app connect`, replace tri-state bool flags with `always|never|ask`, gate auto-expose behind `--expose=ask|always|never`, require explicit `--grant-window` when scope is `window`, accept duration-shaped `--grant-*` values, and deprecate `hasp set` / `hasp capture` / top-level `list`+`get` shortcuts in favor of `hasp secret`.
- Polish the help and error surfaces: 'did you mean' suggestions for unknown topics and commands, distinct empty-vault vs no-match templates, populated `Hint` fields on key user-facing errors, per-command help bodies that list every FlagSet flag, `--dry-run` implies `--explain`, ASCII glyph fallback under non-UTF-8 locales, and an ambient `--json` / `--quiet` sweep across renderers.
- Improve daemon and broker robustness: bump daemon-startup deadline to 15s, replace the os.Stat readiness check with `net.Dial`, memoize `gitsafe.TopLevel` and `CanonicalProjectRoot.EvalSymlinks`, surface `randomHex` entropy failures instead of panicking, detect pid reuse during `session ResolveProcess`, and parse global flags from any argv position.
- Continue the `internal/app` monolith split as foundation work: Stage 1 extracts leaf rendering primitives to `internal/app/ui/`, Stage 2 extracts five cycle-relevant primitives to dedicated subpackages (`internal/app/ttyutil/`, `internal/app/secrettypes/`, `internal/app/auditlog/`, `internal/app/vaultaccess/`, `internal/app/cmddispatch/`) using a closure-indirection pattern that keeps test seams in place with zero test-file churn.
- Allocate a PTY when `hasp run` detects a TTY on stdout so child programs that probe for an interactive terminal keep working through the broker, and add ANSI-aware streaming redaction so terminal control sequences no longer mask sensitive substrings.

## [v0.1.32]

- Close the post-v0.1.31 V1 visibility remainder without widening the product: surface the stdin/shell-export rescue path in `hasp import --help`, write a paste-rescue section plus V1 threat-model-limits and licensing-and-usage blocks into the packaged `QUICKSTART.md`, and align `docs/quickstart.md` with the same blocks.
- Reconcile the competitive baseline against shipped v0.1.31 behavior: refresh `docs/competition/matrix.json` and regenerate matrix.md/matrix.html, rewrite `docs/competition/v1-parity.md` to show that no open V1 parity items remain, and drop onboarding and generic-compatible first-proof lines from the weakest-points section of `docs/competition/v1-v4-market-landscape.md`.
- Keep the Go verification bar at `100.0%` statement coverage across all 13 packages.

## [v0.1.31]

- Finish V1 local-first parity: complete the onboarding eval so `hasp setup --non-interactive --json --bind-imports` reliably yields a ready brokered proof, and expose the generic-compatible first-proof surface through `hasp agent list-supported`, `hasp bootstrap print-config`, and the printed proof command.
- Restore `100.0%` statement coverage across the Go modules and prune internal app drift, keeping the verification bar and maintenance boundaries intact as the product surface grows.

## [v0.1.30]

- Close the remaining V1 competitive gaps without widening the product: refresh the competitive baseline and matrix, restate the real V1 gaps, and add a single-page visual competition matrix to the private docs.
- Reduce internal app drift by splitting the setup workflow into smaller maintenance boundaries.

## [v0.1.29]

- Close V1 conformance ahead of the release: finish scoped conformance work, retire completed roadmap review beads, and mark shipped versus future documentation status.
- Harden the agent-safe broker spec after adversarial review so the brokered-grant semantics stay enforced end-to-end under automated tests and production operator flows.

## [v0.1.28]

- Harden the agent-safe path by switching generated agent configs to managed wrapper scripts, registering protected process trees with the runtime daemon, and resolving agent-safe state from process ancestry before weaker env/repo fallbacks.
- Keep plaintext access inside agent-safe sessions brokered through one-time local approval grants, suppress native approval prompts under automated tests only, and preserve the production operator approval path.
- Raise and retain the Go verification bar at `100.0%` coverage while splitting the agent setup, secret prompt/plaintext policy, and setup coverage hotspots into smaller maintenance boundaries.
- Fix single-tarball verification for the public multi-platform release manifest so operators can verify one downloaded tarball without also downloading every sibling platform archive.

## [v0.1.27]

- Stop temp-home eval and release flows from leaving stray `hasp daemon serve` processes behind, and scope eval-side CLI config writes to the test home instead of the real machine config.
- Harden the cleanup fallback so pidfile-based teardown first verifies that the recorded PID still belongs to the expected scoped HASP daemon before it invokes `daemon stop` or sends kill signals.
- Raise the repo-wide Go verification bar back to `100.0%` coverage and split setup presentation helpers out of `setup.go` so the setup workflow and terminal rendering are no longer concentrated in one file.

## [v0.1.26]

- Harden macOS convenience unlock by targeting the explicit default keychain path for keychain set, get, and delete operations instead of relying on ambient search-list behavior.
- Retry the setup-time convenience-unlock verification step before declaring it unavailable, and surface a concrete convenience-unlock detail in setup output when macOS still blocks the keychain path.
- Keep the repo verification bar at `100.0%` coverage and publish the patch through the signed release, R2 mirror, and Homebrew tap flow.

## [v0.1.25]

- Extend the launcher consent path so HASP can add its launcher directory to shell PATH, but only after the user says yes in interactive flows or passes `--add-to-path=true` in scripts.
- Keep the new topic-based help surface intact while covering the PATH-edit code and rollback paths back to a deterministic `100.0%` Go coverage gate.
- Publish the patch through the real HASP signing key, the GitHub release flow, and the configured R2 mirror.

## [v0.1.24]

- Add a real topic-based CLI help surface under `hasp --help`, `hasp help ...`, and command-local `--help` routes so users can learn the vault, app, agent, project, and broker concepts directly from the binary.
- Make launcher creation explicit in the app flow: interactive `hasp app connect` now asks before it writes a launcher, while scripted runs use `--install=true` or `--install=false`.
- Keep the repo coverage gate at `100.0%`, keep conformance green, and publish the release with the real HASP signing key plus the configured R2 mirror path.

## [v0.1.23]

- Re-cut the consumer-first app and agent release with the real HASP release signing key so the published checksums, tarballs, and detached signatures no longer rely on ephemeral local signing.
- Keep the shipped `hasp secret`, `hasp app`, and `hasp agent` surfaces from `v0.1.22` unchanged while publishing a clean signed patch release.

## [v0.1.22]

- Add the consumer-first `hasp app` and `hasp agent` surfaces, including machine-scoped app consumers, repo-scoped agent connections, audited consumer profile storage, and runtime delivery for env vars, temporary files, and temporary dotenv bundles.
- Harden launcher ergonomics by validating app consumer names, forwarding runtime arguments through `hasp app run`, protecting unmanaged launcher paths from silent overwrite, and preserving rollback coverage for connect, install, and disconnect failure paths.
- Update the V1 and quickstart docs around the shipped consumer model while keeping the Go verification gate at `100.0%` coverage and the full conformance lane green.

## [v0.1.21]

- Add the human-first `hasp secret` CLI surface for add, update, delete, get, list, expose, and hide, plus matching MCP secret tools so coding agents can store and expose secrets without forcing the user out of chat.
- Tighten repo-scoped secret enforcement so brokered execution no longer falls back to raw vault item names and automatic repo enablement only occurs for real git repositories.
- Raise the Go verification bar back to a deterministic `100.0%` coverage gate, add direct branch coverage for the new secret flows, and harden local release signing scripts so ephemeral noninteractive signing works in release smoke and artifact evals.

## [v0.1.20]

- Negotiate the MCP protocol version during `initialize` so Claude accepts `hasp mcp` instead of rejecting the hard-coded `2026-04-13` handshake.
- Keep compatibility with stricter clients by preferring the stable `2025-06-18` MCP protocol while still tolerating clients that explicitly request the newer version.

## [v0.1.19]

- Keep `hasp setup` responsive after password entry by time-bounding the optional macOS convenience-unlock enable and verification path instead of waiting on slow keychain failures.
- Skip macOS convenience-unlock setup entirely when no usable default keychain exists, so setup falls back cleanly instead of surfacing the `Keychain Not Found` system dialog.

## [v0.1.18]

- Stop `hasp mcp` from replying to JSON-RPC notifications, so Codex no longer fails MCP startup with `Transport closed` during the `notifications/initialized` handshake.
- Add regression coverage for the initialize plus notification handshake so future releases keep the MCP stream valid for stricter clients.

## [v0.1.17]

- Rework the interactive `hasp setup` confirmation and completion screens into grouped, aligned blocks so machine defaults, agent targets, statuses, and next steps are easier to scan at a glance.
- Add stronger TTY-only color hierarchy for stage bullets, config paths, summary labels, statuses, and numbered next steps while keeping non-TTY output clean and the `100.0%` coverage gate intact.

## [v0.1.15]

- Support noninteractive GPG signing for public release packaging with `HASP_RELEASE_GPG_PASSPHRASE` or `HASP_RELEASE_GPG_PASSPHRASE_FILE`, so passphrase-protected release keys work in CI and scripted maintainer flows.
- Extend the release smoke lane to cover passphrase-protected signing for both packaged release sidecars and assembled public release metadata, while keeping the public export verification lane green.

## [v0.1.14]

- Tighten the interactive `hasp setup` presentation so stage guidance uses cleaner bullets, TTY color accents, and a standalone success lead instead of the old indented summary line.
- Lock the setup-output polish down with exact-output regressions while keeping the absolute MCP command path fix and the `100.0%` coverage gate intact.

## [v0.1.13]

- Write absolute `hasp` command paths into generated Codex and JSON MCP client configs so launcher environments do not depend on ambient PATH resolution.
- Keep the setup retry fix, convenience-unlock compatibility fix, truthful version reporting, and `100.0%` coverage gate intact.

## [v0.1.12]

- Store convenience-unlock key material in a keychain-compatible encoded form and decode it on readback, so macOS convenience unlock works reliably on real installed binaries.
- Keep the existing-vault setup retry fix, truthful embedded version reporting, and `100.0%` coverage gate intact.

## [v0.1.11]

- Embed the build version into HASP binaries so `hasp version` reports the binary’s own release identity instead of reading a nearby repo `VERSION` file from the current working directory.
- Keep the existing-vault setup retry fix and `100.0%` coverage gate intact while making stale installed binaries easier to detect.

## [v0.1.10]

- Re-cut the setup retry fix release from a real-PTY-validated `HEAD` so the published version is unambiguous.
- Preserve the existing-vault password retry behavior, convenience-unlock verification, and the integration regressions added for both paths.

## [v0.1.9]

- Keep interactive `hasp setup` on the existing-vault password prompt after a wrong password instead of aborting the whole flow.
- Add integration coverage for the exact retry path so future releases catch this regression automatically.

## [v0.1.8]

- Verify convenience unlock during `hasp setup` by reopening the vault through the keychain path before reporting success.
- Return a clearer CLI error when neither `HASP_MASTER_PASSWORD` nor convenience unlock is available for a vault-opening command.
- Add integration coverage for the exact setup/status regression so future releases catch this mismatch automatically.

## [v0.1.7]

- Add `hasp project adopt --under <dir> [--preview]` so operators can scan and enroll multiple local git repos using machine defaults without background crawling.
- Extend the CLI integration coverage and edge-case tests for bulk adoption and password-iteration selection, bringing the repo Go coverage gate back to `100.0%`.
- Keep the curated public export boundary valid while landing the new V1 adoption path.

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
