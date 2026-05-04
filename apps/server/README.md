# HASP server module

This directory builds the `hasp` CLI and local broker.

The module path is `github.com/gethasp/hasp/apps/server`. Keep the
`apps/server` path unless you are ready to update Go imports, release scripts,
docs, and packaging together.

## What lives here

- `cmd/hasp/` contains the end-user CLI.
- `cmd/release-sign/` contains release signing support.
- `internal/app/` wires CLI commands to broker and vault operations.
- `internal/runtime/` manages daemon lifecycle and local process state.
- `internal/store/` owns the encrypted vault and import path.
- `internal/mcp/` exposes the local MCP integration.
- `internal/runner/` handles brokered command execution.
- `profiles/` and `testdata/profiles/` hold agent profile fixtures.

Most product behavior enters through `cmd/hasp` and is implemented under
`internal/`. Public API packages should be added only when another module needs
a stable import surface.

## Local development

From the repo root:

```bash
make build
make test
make lint
make coverage
```

From this directory:

```bash
make test
make lint
make staticcheck
make vulncheck
```

The test wrappers pass the `hasp_test_fastkdf` build tag. Use those wrappers for
normal runs so vault tests do not pay production Argon2id costs.

For a targeted package run:

```bash
go test -tags=hasp_test_fastkdf -run 'TestName' ./internal/app
```

Avoid raw full sweeps without the tag.

## Release and verification paths

Release packaging is driven from the repo root:

```bash
make package-release
make package-public-release
make release-smoke
make conformance
```

The scripts under `../../scripts` are part of the public release surface when
they build, test, package, verify, publish, or install the CLI/broker.

## Docs

Use the root docs for operator-facing behavior:

- [../../QUICKSTART.md](../../QUICKSTART.md)
- [../../docs/command-guide.md](../../docs/command-guide.md)
- [../../docs/cli-reference.md](../../docs/cli-reference.md)
- [../../docs/operator-guide.md](../../docs/operator-guide.md)
- [../../docs/error-codes.md](../../docs/error-codes.md)
