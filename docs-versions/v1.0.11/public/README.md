# HASP

HASP is a local secret broker for coding agents.

Agents need credentials to run tests, call APIs, and deploy code. Copying those
credentials into prompts, shell history, `.env` files, or repo-local notes makes
the agent faster today and harder to trust tomorrow. HASP keeps secrets in a
local encrypted vault and gives commands only the values they are allowed to use
at runtime.

The core rule is:

Managed secret values must not enter agent context.

## Install

Use Homebrew for normal installs on macOS and Linux:

```bash
brew tap gethasp/tap
brew install gethasp/tap/hasp
hasp version
```

Then run the guided setup:

```bash
hasp setup
```

For source builds:

```bash
make build
bin/hasp version
```

See [install.md](docs/install.md) for packaged release verification, upgrades,
and uninstall steps. `hasp upgrade --version vX.Y.Z` fetches and verifies a
signed release in place; run `hasp help upgrade` for flags and trust roots.

## First proof

Add a secret, connect a project, and run a command through the broker:

```bash
hasp secret add
hasp app connect
hasp app run -- sh -c 'test -n "$API_TOKEN"'
```

For the full first-run path, start with [QUICKSTART.md](QUICKSTART.md). For the
operating model behind vaults, grants, bindings, and agent profiles, read
[mental-model.md](docs/mental-model.md).

## What HASP does

- stores managed secrets in a local encrypted vault
- brokers secret access to commands and agent tooling
- supports `run`, `inject`, MCP, and app connection flows
- materializes plaintext only when an operator asks for that tradeoff
- installs repo hooks that block managed secrets from commits and deploy paths
- keeps audit records for brokered secret use
- keeps telemetry disabled unless you explicitly opt in

HASP is local-first. It does not require a hosted control plane for v1.

## Repo layout

```text
.
|-- apps/server/        # Go module for the hasp CLI and local broker
|-- docs/               # Public product and operator docs
|-- scripts/            # Public build, test, install, release, and verification helpers
|-- Makefile            # Common local and CI entry points
`-- QUICKSTART.md       # Shortest path to a working local install
```

The Go code lives in `apps/server` because the released module path is
`github.com/gethasp/hasp/apps/server`. Keeping that path stable avoids breaking
imports, release scripts, Homebrew packaging, and downstream source builds.

## Development

Use the root Makefile for normal local work:

```bash
make build
make test
make lint
make verify-ci
```

The server module has the same focused targets under `apps/server`:

```bash
make -C apps/server test
make -C apps/server coverage
```

Script details are in [scripts/README.md](scripts/README.md). Server internals
are in [apps/server/README.md](apps/server/README.md).

## Docs

- [install.md](docs/install.md) covers Homebrew and packaged releases.
- [after-homebrew.md](docs/after-homebrew.md) covers first setup after install.
- [command-guide.md](docs/command-guide.md) maps jobs to commands.
- [cli-reference.md](docs/cli-reference.md) lists generated command help.
- [operator-guide.md](docs/operator-guide.md) covers day-to-day operations.
- [telemetry.md](docs/telemetry.md) covers opt-in CLI telemetry, payloads,
  retention, erasure, and the hard runtime kill switch.
- [value-free-manifests.md](docs/value-free-manifests.md) explains safe manifests.
- [agent profiles](docs/agent-profiles/README.md) cover the six first-class
  profiles (Codex CLI, Claude Code, Cursor, Aider, Hermes, OpenClaw) and the
  generic broker path. `hasp agent connect <id>` writes the MCP config in
  place for `claude-code`, `codex-cli`, and `cursor`; for `aider`, `hermes`,
  and `openclaw` it installs the wrapper at `$HASP_HOME/bin/hasp-agent-<id>`
  and you wire it into the agent per the matching profile doc.

The full docs index is [docs/README.md](docs/README.md).

## Security

Report security issues through [SECURITY.md](SECURITY.md). Please do not open a
public issue for a suspected vulnerability.

## License

HASP is source-available under the Fair Core License. See [LICENSE](LICENSE).
