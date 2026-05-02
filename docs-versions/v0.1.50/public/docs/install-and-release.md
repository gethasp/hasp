# Install and release

This page covers the public install path and the release trust path together.

## Homebrew

Use Homebrew for the normal public install path:

```bash
brew tap gethasp/homebrew-tap
brew install hasp
hasp version
```

Use [Install](install.md) for Homebrew upgrade and uninstall commands.

## Hosted release layout

GitHub Releases are the canonical hosted asset location.

The optional [R2 mirror](https://download.gethasp.com/), when configured for the same byte set, uses `https://downloads.gethasp.com/hasp/releases/<tag>/`.

## Documentation release gate

Do not cut a tag until the docs match the release.

Before creating a tag:

1. Update every public doc page affected by new or exposed functionality.
2. Update examples, command output, install steps, agent profile pages, and error guidance when behavior changes.
3. Add any new docs page to the docs index/navigation source.
4. Publish the matching versioned docs from the canonical release source.
5. Keep the release gate process-bounded: the Go test wrapper defaults package
   parallelism to `-p 1`, and daemon lifecycle changes should leave no
   `app.test daemon serve`, `runtime.test daemon serve`, or
   `hasp-evals-bin*/hasp daemon serve` helpers behind.

The public `/docs/` route and the release route `/docs/vX.Y.Z/` must describe
the tag that is about to be published.

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
