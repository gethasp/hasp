# HASP

HASP is a local-first broker for managed secrets in agent workflows.

It is built for people using coding agents on normal developer machines who
need the agent to do useful work without turning `.env` files, copied tokens,
and repo-local credentials into the default operating model.

## What this public repo contains

This repo contains the public code and release surface for:

- the Go broker and CLI under `apps/server/`
- the future native macOS app surface under `apps/macos/`
- the public docs needed to build, test, verify, and install shipped releases

This repo does not contain the marketing site, the future cloud control plane,
or the internal product/research docs used in the source-of-truth repo.

## What HASP does

- stores managed secrets in a local encrypted vault
- brokers secret access to commands and agent tooling
- supports safe brokered execution through `run`, `inject`, and MCP flows
- provides audited convenience materialization when an operator explicitly asks
  for it
- installs repo guardrails so managed secrets do not get committed or deployed
  by accident

The core rule is simple:

In broker-managed agent-safe flows, managed secret values must not enter agent
context.

## Start locally

Source build:

```bash
make build
bin/hasp version
```

Packaged release:

```bash
scripts/hasp-verify-release.sh dist/release/hasp_<version>_<os>_<arch>.tar.gz
scripts/hasp-install-release.sh --verify dist/release/hasp_<version>_<os>_<arch>.tar.gz
```

If you want the short path first, start with [QUICKSTART.md](QUICKSTART.md).

## Release model

- tagged releases publish signed release artifacts
- release assets can be mirrored to Cloudflare R2 behind a stable download host
- Homebrew support is artifact-based, not source-build-based

For the maintainer flow, see [RELEASING.md](RELEASING.md).

## Public repo rule

This repo is a curated public export of the canonical source tree.

If maintainers accept a public PR, they replay the change through the canonical
source tree and sync the public export back here before merging or tagging the
release.

## Where to go next

- [QUICKSTART.md](QUICKSTART.md)
- [docs/README.md](docs/README.md)
- [SUPPORT.md](SUPPORT.md)
- [SECURITY.md](SECURITY.md)
- [CONTRIBUTING.md](CONTRIBUTING.md)
