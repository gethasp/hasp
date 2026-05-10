# HASP docs

These docs cover the public CLI, local broker, release packages, and operator
workflows.

## Start here

- [Install HASP](install.md): Homebrew, packaged releases, upgrades, and
  uninstall paths.
- [After Install](after-homebrew.md): the guided setup flow after `hasp setup`.
- [Mental model](mental-model.md): vaults, bindings, grants, brokered command
  delivery, and safe agent use.
- [Command guide](command-guide.md): common jobs mapped to the right command.
- [CLI reference](cli-reference.md): generated command help for the current
  release.

## Operate HASP

- [Operator guide](operator-guide.md): setup, agent connection, guardrails, and
  troubleshooting.
- [Value-free manifests](value-free-manifests.md): how to describe secret use
  without storing secret values.
- [Agent profiles](agent-profiles/README.md): Codex, Claude Code, Cursor,
  Aider, and generic agent setups.
- [Error codes](error-codes.md): stable process exit codes and error envelopes.
- [Glossary](glossary.md): product terms used by command output and docs.

## Build and release

- [Install and release](install-and-release.md): packaged release mechanics.
- [macOS v2 migration](macos-v2-migration.md): formula versus cask install
  paths for the free CLI and paid Mac app.
- [Release distribution](release-distribution.md): artifact layout and mirrors.
- [Repo targets](repo-targets.md): supported release targets.
- [V1 production guide](v1-production-guide.md): production readiness checks for
  the local broker.

The root [README](../README.md) explains the repo layout and development
targets.
