# Quickstart

This file covers the shortest safe path to a working local HASP install.

If you already installed HASP and want the full beginner flow, read
[After Install](docs/after-homebrew.md).

For the simplest first-run path, use:

```bash
hasp setup
```

Interactive setup can now stop after machine setup, skip agent setup, or
continue directly into adding a secret and connecting one app.

To learn the CLI directly from the binary, use:

```bash
hasp --help
hasp help secret
hasp help app connect
```

The manual steps below remain the fallback path and the troubleshooting reference.

## Current UX

The current build supports both the lower-level broker commands and the newer
consumer commands:

- `hasp secret add`
- `hasp app connect`
- `hasp app run`
- `hasp app install`
- `hasp agent connect`

Use the consumer commands for normal vault, app, and agent setup. Keep
`hasp run`, `hasp inject`, and `hasp write-env` for advanced brokered flows.

## 1. Build or download a release

From source:

```bash
make build
bin/hasp version
```

From a packaged release:

```bash
scripts/hasp-verify-release.sh dist/release/hasp_<version>_<os>_<arch>.tar.gz
scripts/hasp-install-release.sh --verify dist/release/hasp_<version>_<os>_<arch>.tar.gz
```

The packaged verifier expects these sidecars next to the tarball:

- `SHA256SUMS`
- `SHA256SUMS.asc`
- `hasp-release-public-key.asc`
- `<artifact>.tar.gz.asc`
- `<artifact>_bin.asc`

## 2. Initialize the local vault

```bash
export HASP_MASTER_PASSWORD='choose-a-strong-password'
bin/hasp init
```

## 3. Import a secret file

```bash
bin/hasp import .env
bin/hasp import service-account.json
```

Or add one directly without creating a temp file:

```bash
bin/hasp secret add
```

## 4. Bind a repo and install guardrails

```bash
bin/hasp bootstrap \
  --profile codex-cli \
  --project-root /path/to/repo \
  --alias secret_01=API_TOKEN
```

If you are already inside the repo and just want to save a secret and use it
there, the human-first path is now:

```bash
cd /path/to/repo
bin/hasp secret add
```

If you already enabled automatic repo adoption and want to enroll several local
git repos at once, use:

```bash
bin/hasp project adopt --under /path/to/workspaces --preview
bin/hasp project adopt --under /path/to/workspaces
```

That scans for git-backed project roots, skips non-project directories, and
binds the matching repos using the machine defaults from `hasp setup`.

## 5. Use the brokered path

```bash
bin/hasp run \
  --project-root /path/to/repo \
  --env API_TOKEN=secret_01 \
  --grant-project window \
  --grant-secret session \
  --grant-window 15m \
  -- sh -c 'printf "%s" "$API_TOKEN"'
```

## 6. Upgrade or uninstall

```bash
scripts/hasp-upgrade-release.sh --verify dist/release/hasp_<new-version>_<os>_<arch>.tar.gz
scripts/hasp-uninstall-release.sh ~/.local/share/hasp/hasp_<version>_<os>_<arch>
```

The default uninstall path removes only the installed release tree. It does not
remove `HASP_HOME` or repo hooks unless you pass explicit cleanup flags.

## Known limits of v1

- V1 is local-first. There is no hosted control plane.
- V1 reduces accidental exposure on a normal developer machine. It does not provide strong same-user local isolation.
- HASP does not manage your PATH by default. App launchers and PATH edits require explicit consent.
- Pasted values and shell exports become managed only after you import or capture them.
- `hasp write-env`, `hasp secret reveal`, and `hasp secret copy` put plaintext back in human-visible places. Use them when that tradeoff is intentional.

## Where to go next

- Read the [mental model](docs/mental-model.md) to understand vaults, bindings, grants, and brokered delivery.
- Use the [command guide](docs/command-guide.md) when you know the job but not the command.
- Keep the [glossary](docs/glossary.md) nearby when command output uses a term you do not recognize.
