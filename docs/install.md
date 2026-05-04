# Install HASP

Use Homebrew for normal installs on macOS and Linux. Use the packaged release
scripts when you need to verify a tarball by hand or install into a custom
prefix.

## Install with Homebrew

```bash
brew tap gethasp/tap
brew install gethasp/tap/hasp
hasp version
```

If you already added the tap, `brew install gethasp/tap/hasp` is enough.

After install, continue with [After Install](after-homebrew.md):

```bash
hasp setup
```

## Upgrade with Homebrew

```bash
brew update
brew upgrade hasp
hasp version
```

Run `hasp doctor` after upgrading if a daemon is already running. It reports
CLI and daemon version mismatch.

## Uninstall with Homebrew

```bash
brew uninstall hasp
```

Homebrew removes the formula files. It does not remove your HASP vault,
`HASP_HOME`, repo hooks, app launchers, or audit history. Remove those only when
you are intentionally decommissioning the local install.

## Direct packaged release

Use this path when you downloaded a release tarball and want local signature
verification before install:

```bash
scripts/hasp-verify-release.sh dist/release/hasp_<version>_<os>_<arch>.tar.gz
scripts/hasp-install-release.sh --verify dist/release/hasp_<version>_<os>_<arch>.tar.gz
```

Default install prefix:

```bash
$HOME/.local/share/hasp/hasp_<version>_<os>_<arch>
```

Installed binary:

```bash
$HOME/.local/share/hasp/hasp_<version>_<os>_<arch>/bin/hasp
```

## Upgrade a packaged release

```bash
scripts/hasp-upgrade-release.sh --verify \
  dist/release/hasp_<new-version>_<os>_<arch>.tar.gz \
  "$HOME/.local/share/hasp/hasp_<old-version>_<os>_<arch>"
```

You can also use the CLI upgrade command when you want HASP to fetch and verify
a published release:

```bash
hasp upgrade --version v1.0.0 --yes
```

## Uninstall a packaged release

```bash
scripts/hasp-uninstall-release.sh "$HOME/.local/share/hasp/hasp_<version>_<os>_<arch>"
```

The default uninstall path removes the installed release tree only. Pass
`--remove-hooks-from <repo>` or `--purge-hasp-home <path>` only when that cleanup
is intentional.

## Source build

Use source builds for development:

```bash
make build
bin/hasp version
```

Source builds are not the normal user install path.
