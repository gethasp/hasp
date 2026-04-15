# Install HASP

## Source build

```bash
make build
bin/hasp version
```

## Packaged release

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

## Upgrade

```bash
scripts/hasp-upgrade-release.sh --verify dist/release/hasp_<new-version>_<os>_<arch>.tar.gz
```

## Uninstall

```bash
scripts/hasp-uninstall-release.sh ~/.local/share/hasp/hasp_<version>_<os>_<arch>
```

The default uninstall path removes the installed release tree only.
