# Quickstart

This file covers the shortest safe path to a working local HASP install.

If you already installed HASP with Homebrew and want the full beginner flow,
read [docs/after-homebrew.md](docs/after-homebrew.md).

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

## 4. Bind a repo and install guardrails

```bash
bin/hasp bootstrap \
  --profile codex-cli \
  --project-root /path/to/repo \
  --alias secret_01=API_TOKEN
```

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

## Boundaries to remember

- V1 is local-first and reduces accidental exposure on a normal developer
  machine.
- V1 is not strong same-user local isolation.
- brokered flows are safer than direct exports or pasted values.
- convenience materialization is an explicit operator tradeoff, not the default
  trust model.
