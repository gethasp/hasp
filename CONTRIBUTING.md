# Contributing to HASP

Thanks for taking a look.

Keep changes narrow, keep docs in sync with behavior, and prefer clear code
over clever code.

## Before you open a pull request

1. Read [README.md](README.md) and [QUICKSTART.md](QUICKSTART.md).
2. Read [SUPPORT.md](SUPPORT.md) and [SECURITY.md](SECURITY.md).
3. Run the smallest relevant verification for the files you changed.
4. Keep the public/private boundary intact. Do not introduce web, cloud,
   marketing, or internal-only docs into this repo.

## Development workflow

Run commands from the repo root.

Fast local loop:

```bash
make build
make test
make lint
```

Full verification before a substantial PR:

```bash
make verify
make release-smoke
make coverage
```

## Pull request rules

- Keep each PR about one thing.
- Add or update tests when behavior changes.
- Update docs when commands, packaging, install flow, or release flow change.
- Before a tag is cut, maintainers update the public docs for every new or exposed behavior and publish the matching versioned docs from the canonical source.
- Use non-interactive Git commands.
- Keep commits small enough to roll back cleanly.

## Clean-room rule

This public repo is an exported release surface, not the full internal product
repo.

Do not add:

- marketing site code
- cloud control-plane code
- private research or planning docs
- internal release credentials or ops-only notes

If a maintainer accepts a public PR, they replay it through the canonical
source tree before syncing the result back here.
