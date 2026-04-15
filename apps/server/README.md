# apps/server

This directory is the home of the HASP Go broker/runtime.

Expected future contents:

- `cmd/hasp/`
- `internal/`
- `pkg/` only if needed for app-specific exported code
- app-local `go.mod`
- app-local `Makefile`

The root `Makefile` proxies the main server build/test/lint flows into this directory.

Current local workflows:

- `make build`
- `make test`
- `make release-smoke`
- `make package-release`
