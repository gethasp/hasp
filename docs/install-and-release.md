# Install and release

This page covers the public install path and the release trust path together.

## Homebrew

Use Homebrew for the normal public install path:

```bash
brew install hasp
hasp version
```

The planned public tap is `gethasp/homebrew-tap`.

## Hosted release layout

GitHub Releases are the canonical hosted asset location.

The optional [R2 mirror](https://download.gethasp.com/), when configured for the same byte set, uses `https://downloads.gethasp.com/hasp/releases/<tag>/`.

## Source build

```bash
make build
```

The local binary lands at `bin/hasp`.

## Direct packaged release

```bash
scripts/hasp-verify-release.sh hasp_<version>_<os>_<arch>.tar.gz
scripts/hasp-install-release.sh --verify hasp_<version>_<os>_<arch>.tar.gz
```

Lifecycle helpers:

```bash
scripts/hasp-upgrade-release.sh --verify hasp_<version>_<os>_<arch>.tar.gz /path/to/install-dir
scripts/hasp-uninstall-release.sh /path/to/install-dir
```

## Release trust path

- verify the signed checksum manifest
- verify the tarball signature
- verify the packaged binary signature
- install only the exact release bytes that were published
